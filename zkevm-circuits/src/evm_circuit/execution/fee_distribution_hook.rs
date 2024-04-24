use super::ExecutionGadget;
use crate::{
    evm_circuit::{
        param::{MAX_N_BYTES_INTEGER, N_BYTES_U64},
        step::ExecutionState,
        util::{
            common_gadget::UpdateBalanceGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            from_bytes,
            math_gadget::LtGadget,
            CachedRegion, Cell, U64Word, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{CallContextFieldTag, TxContextFieldTag},
    util::Expr,
};
use eth_types::{
    kroma_params::{
        L1_BLOCK, PROTOCOL_VAULT, REWARD_DENOMINATOR, VALIDATOR_REWARD_SCALAR_KEY,
        VALIDATOR_REWARD_VAULT,
    },
    Field, ToLittleEndian, ToScalar, U256,
};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

#[derive(Clone, Debug)]
pub(crate) struct FeeDistributionHookGadget<F> {
    tx_id: Cell<F>,
    tx_gas: Cell<F>,
    tx_gas_price_word: Word<F>,
    validator_reward_scalar_word: Word<F>,
    validator_reward_scalar_committed_word: Word<F>,
    remainder_word: U64Word<F>,
    lt: LtGadget<F, N_BYTES_U64>,
    protocol_reward_vault: Cell<F>,
    protocol_received_reward: UpdateBalanceGadget<F, 2, true>,
    validator_reward_vault: Cell<F>,
    validator_received_reward: UpdateBalanceGadget<F, 2, true>,
}

impl<F: Field> ExecutionGadget<F> for FeeDistributionHookGadget<F> {
    const NAME: &'static str = "FeeDistributionHook";

    const EXECUTION_STATE: ExecutionState = ExecutionState::FeeDistributionHook;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let tx_gas = cb.tx_context(tx_id.expr(), TxContextFieldTag::Gas, None);
        let gas_used = tx_gas.expr() - cb.curr.state.gas_left.expr();
        let tx_gas_price_word =
            cb.tx_context_as_word(tx_id.expr(), TxContextFieldTag::GasPrice, None);

        let l1_block_address = Expression::Constant(
            L1_BLOCK
                .to_scalar()
                .expect("L1 BLOCK should be able to be converted to scalar value"),
        );
        let validator_reward_scalar_word = cb.query_word_rlc();
        let validator_reward_scalar_committed_word = cb.query_word_rlc();
        let key_le_bytes: [u8; 32] = (*VALIDATOR_REWARD_SCALAR_KEY).to_le_bytes();
        cb.account_storage_read(
            l1_block_address.expr(),
            cb.word_rlc(key_le_bytes.map(|b| b.expr())),
            validator_reward_scalar_word.expr(),
            tx_id.expr(),
            validator_reward_scalar_committed_word.expr(),
        );

        let protocol_reward_word = cb.query_word_rlc();
        let validator_reward_word = cb.query_word_rlc();
        let remainder_word = cb.query_word_rlc();

        let [protocol_reward, validator_reward, validator_reward_scalar, tx_gas_price] = [
            &protocol_reward_word,
            &validator_reward_word,
            &validator_reward_scalar_word,
            &tx_gas_price_word,
        ]
        .map(|word| from_bytes::expr(&word.cells[..MAX_N_BYTES_INTEGER]));
        let [remainder] =
            [&remainder_word].map(|word| from_bytes::expr(&word.cells[..N_BYTES_U64]));
        cb.require_equal(
            "gas_used * tx_gas_price * validator_reward_scalar == REWARD_DENOMINATOR * validator_reward + remainder",
            gas_used.clone() * tx_gas_price.clone() * validator_reward_scalar,
            REWARD_DENOMINATOR.as_u64().expr() * validator_reward.clone() + remainder.clone(),
        );
        let lt = LtGadget::construct(cb, REWARD_DENOMINATOR.as_u64().expr(), remainder.expr());
        cb.require_zero("remainder < 10000", lt.expr());

        cb.require_equal(
            "gas_used * tx_gas_price == protocol_reward + validator_reward",
            gas_used.expr() * tx_gas_price,
            protocol_reward + validator_reward,
        );

        // protocol reward
        let protocol_reward_vault = cb.query_cell();
        let protocol_received_reward = UpdateBalanceGadget::construct(
            cb,
            protocol_reward_vault.expr(),
            vec![protocol_reward_word],
            None,
            None,
        );

        // validator reward
        let validator_reward_vault = cb.query_cell();
        let validator_received_reward = UpdateBalanceGadget::construct(
            cb,
            validator_reward_vault.expr(),
            vec![validator_reward_word],
            None,
            None,
        );

        cb.require_step_state_transition(StepStateTransition {
            rw_counter: Delta(4.expr()),
            ..StepStateTransition::any()
        });

        Self {
            tx_id,
            tx_gas,
            tx_gas_price_word,
            validator_reward_scalar_word,
            validator_reward_scalar_committed_word,
            remainder_word,
            lt,
            validator_reward_vault,
            validator_received_reward,
            protocol_reward_vault,
            protocol_received_reward,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let (protocol_reward_vault_balance, protocol_reward_vault_balance_prev) =
            block.rws[step.rw_indices[2]].account_value_pair();
        let (validator_reward_vault_balance, validator_reward_vault_balance_prev) =
            block.rws[step.rw_indices[3]].account_value_pair();

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
        self.tx_gas
            .assign(region, offset, Value::known(F::from(tx.gas)))?;
        self.tx_gas_price_word
            .assign(region, offset, Some(tx.gas_price.to_le_bytes()))?;
        let validator_reward_scalar = block.l1_fee.validator_reward_scalar;
        self.validator_reward_scalar_word.assign(
            region,
            offset,
            Some(validator_reward_scalar.to_le_bytes()),
        )?;
        self.validator_reward_scalar_committed_word.assign(
            region,
            offset,
            Some(block.l1_fee_committed.validator_reward_scalar.to_le_bytes()),
        )?;

        let gas_used = tx.gas - step.gas_left;
        let total_reward = U256::from(gas_used) * tx.gas_price;

        // gas_used * tx_gas_price * validator_reward_scalar / REWARD_DENOMINATOR
        let (validator_reward, remainder) =
            (total_reward * validator_reward_scalar).div_mod(*REWARD_DENOMINATOR);
        let protocol_reward = total_reward - validator_reward;

        self.remainder_word
            .assign(region, offset, Some(remainder.as_u64().to_le_bytes()))?;

        self.lt.assign_value(
            region,
            offset,
            Value::known(F::from(REWARD_DENOMINATOR.as_u64())),
            Value::known(F::from(remainder.as_u64())),
        )?;

        // protocol reward
        self.protocol_reward_vault.assign(
            region,
            offset,
            Value::known(
                PROTOCOL_VAULT
                    .to_scalar()
                    .expect("unexpected Address(PROTOCOL_VAULT) -> Scalar conversion failure"),
            ),
        )?;

        self.protocol_received_reward.assign(
            region,
            offset,
            protocol_reward_vault_balance_prev,
            vec![protocol_reward],
            protocol_reward_vault_balance,
        )?;

        // validator reward
        self.validator_reward_vault.assign(
            region,
            offset,
            Value::known(
                VALIDATOR_REWARD_VAULT.to_scalar().expect(
                    "unexpected Address(VALIDATOR_REWARD_VAULT) -> Scalar conversion failure",
                ),
            ),
        )?;
        self.validator_received_reward.assign(
            region,
            offset,
            validator_reward_vault_balance_prev,
            vec![validator_reward],
            validator_reward_vault_balance,
        )?;

        Ok(())
    }
}
