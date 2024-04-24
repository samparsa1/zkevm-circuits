use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
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
        BASE_FEE_KEY, BASE_FEE_SCALAR_KEY, BLOB_BASE_FEE_KEY, ECOTONE_COST_DENOMINATOR, L1_BLOCK,
        PROPOSER_REWARD_VAULT,
    },
    Field, ToBigEndian, ToLittleEndian, ToScalar,
};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

#[derive(Clone, Debug)]
pub(crate) struct ProposerRewardHookGadget<F> {
    tx_id: Cell<F>,
    base_fee_word: Word<F>,
    base_fee_committed_word: Word<F>,
    base_fee_scalar_word: Word<F>,
    base_fee_scalar_committed_word: Word<F>,
    blob_base_fee_word: Word<F>,
    blob_base_fee_committed_word: Word<F>,
    tx_rollup_data_gas_cost: Cell<F>,
    remainder_word: U64Word<F>,
    l1_base_fee_scalar_word: U64Word<F>,
    l1_blob_base_fee_scalar_word: U64Word<F>,
    proposer_reward_vault: Cell<F>,
    proposer_reward: UpdateBalanceGadget<F, 2, true>,
    lt: LtGadget<F, N_BYTES_U64>,
}

impl<F: Field> ExecutionGadget<F> for ProposerRewardHookGadget<F> {
    const NAME: &'static str = "ProposerRewardHookGadget";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ProposerRewardHook;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let base_fee_word = cb.query_word_rlc();
        let base_fee_committed_word = cb.query_word_rlc();
        let base_fee_scalar_word = cb.query_word_rlc();
        let base_fee_scalar_committed_word = cb.query_word_rlc();
        let blob_base_fee_word = cb.query_word_rlc();
        let blob_base_fee_committed_word = cb.query_word_rlc();

        let [base_fee, blob_base_fee] = [&base_fee_word, &blob_base_fee_word]
            .map(|word| from_bytes::expr(&word.cells[..MAX_N_BYTES_INTEGER]));

        let l1_block_address = Expression::Constant(
            L1_BLOCK
                .to_scalar()
                .expect("L1 BLOCK should be able to be converted to scalar value"),
        );
        for (i, slot_key) in [*BASE_FEE_KEY, *BASE_FEE_SCALAR_KEY, *BLOB_BASE_FEE_KEY]
            .iter()
            .enumerate()
        {
            let key_le_bytes = slot_key.to_le_bytes();
            let values = match i {
                0 => Some((base_fee_word.expr(), base_fee_committed_word.expr())),
                1 => Some((
                    base_fee_scalar_word.expr(),
                    base_fee_scalar_committed_word.expr(),
                )),
                2 => Some((
                    blob_base_fee_word.expr(),
                    blob_base_fee_committed_word.expr(),
                )),
                _ => None,
            };
            if let Some((value, committed_value)) = values {
                cb.account_storage_read(
                    l1_block_address.expr(),
                    cb.word_rlc(key_le_bytes.map(|b| b.expr())),
                    value,
                    tx_id.expr(),
                    committed_value,
                );
            }
        }

        // Add l1 rollup fee to proposer_reward_vault's balance
        let tx_rollup_data_gas_cost =
            cb.tx_context(tx_id.expr(), TxContextFieldTag::RollupDataGasCost, None);

        let tx_l1_fee_word = cb.query_word_rlc();
        let remainder_word = cb.query_word_rlc();

        let l1_base_fee_scalar_word = cb.query_word_rlc();
        let l1_blob_base_fee_scalar_word = cb.query_word_rlc();

        let tx_l1_fee = from_bytes::expr(&tx_l1_fee_word.cells[..MAX_N_BYTES_INTEGER]);
        let [remainder, l1_base_fee_scalar, l1_blob_base_fee_scalar] = [
            &remainder_word,
            &l1_base_fee_scalar_word,
            &l1_blob_base_fee_scalar_word,
        ]
        .map(|word| from_bytes::expr(&word.cells[..N_BYTES_U64]));

        // TODO(chokobole): Need to check whether `base_fee_scalar` and `blob_base_fee_scalar` is
        // actually derived correctly.
        cb.require_equal(
            "tx_rollup_data_gas_cost * (base_fee * 16 * base_fee_scalar + blob_base_fee * blob_base_fee_scalar) == 16e6 * tx_l1_fee + remainder",
            tx_rollup_data_gas_cost.expr()
                * (base_fee.expr() * 16.expr() * l1_base_fee_scalar.expr()
                    + blob_base_fee.expr() * l1_blob_base_fee_scalar.expr()),
            ECOTONE_COST_DENOMINATOR.as_u64().expr() * tx_l1_fee.clone() + remainder.clone(),
        );
        let lt = LtGadget::construct(
            cb,
            ECOTONE_COST_DENOMINATOR.as_u64().expr(),
            remainder.expr(),
        );
        cb.require_zero("remainder < 16e6", lt.expr());

        let proposer_reward_vault = cb.query_cell();
        let proposer_reward = UpdateBalanceGadget::construct(
            cb,
            proposer_reward_vault.expr(),
            vec![tx_l1_fee_word],
            None,
            None,
        );

        cb.require_step_state_transition(StepStateTransition {
            rw_counter: Delta(5.expr()),
            ..StepStateTransition::any()
        });

        Self {
            tx_id,
            base_fee_word,
            base_fee_committed_word,
            base_fee_scalar_word,
            base_fee_scalar_committed_word,
            blob_base_fee_word,
            blob_base_fee_committed_word,
            tx_rollup_data_gas_cost,
            remainder_word,
            l1_base_fee_scalar_word,
            l1_blob_base_fee_scalar_word,
            proposer_reward_vault,
            proposer_reward,
            lt,
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
        let (base_fee, _, _, base_fee_committed) =
            block.rws[step.rw_indices[1]].storage_value_aux();
        let (base_fee_scalar, _, _, base_fee_scalar_committed) =
            block.rws[step.rw_indices[2]].storage_value_aux();
        let (blob_base_fee, _, _, blob_base_fee_committed) =
            block.rws[step.rw_indices[3]].storage_value_aux();
        let (proposer_reward_vault_balance, proposer_reward_vault_balance_balance_prev) =
            block.rws[step.rw_indices[4]].account_value_pair();

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
        self.base_fee_word
            .assign(region, offset, Some(base_fee.to_le_bytes()))?;
        self.base_fee_committed_word.assign(
            region,
            offset,
            Some(base_fee_committed.to_le_bytes()),
        )?;
        self.base_fee_scalar_word
            .assign(region, offset, Some(base_fee_scalar.to_le_bytes()))?;
        self.base_fee_scalar_committed_word.assign(
            region,
            offset,
            Some(base_fee_scalar_committed.to_le_bytes()),
        )?;
        self.blob_base_fee_word
            .assign(region, offset, Some(blob_base_fee.to_le_bytes()))?;
        self.blob_base_fee_committed_word.assign(
            region,
            offset,
            Some(blob_base_fee_committed.to_le_bytes()),
        )?;
        self.tx_rollup_data_gas_cost.assign(
            region,
            offset,
            Value::known(F::from(tx.rollup_data_gas_cost)),
        )?;

        let l1_base_fee_scalar_bytes = block.l1_fee.base_fee_scalar.to_be_bytes();
        const L1_BASE_FEE_SCALAR_OFFSET: usize = 16;
        let l1_base_fee_scalar = u32::from_be_bytes([
            l1_base_fee_scalar_bytes[L1_BASE_FEE_SCALAR_OFFSET],
            l1_base_fee_scalar_bytes[L1_BASE_FEE_SCALAR_OFFSET + 1],
            l1_base_fee_scalar_bytes[L1_BASE_FEE_SCALAR_OFFSET + 2],
            l1_base_fee_scalar_bytes[L1_BASE_FEE_SCALAR_OFFSET + 3],
        ]);
        const L1_BLOB_BASE_FEE_SCALAR_OFFSET: usize = 12;
        let l1_blob_base_fee_scalar = u32::from_be_bytes([
            l1_base_fee_scalar_bytes[L1_BLOB_BASE_FEE_SCALAR_OFFSET],
            l1_base_fee_scalar_bytes[L1_BLOB_BASE_FEE_SCALAR_OFFSET + 1],
            l1_base_fee_scalar_bytes[L1_BLOB_BASE_FEE_SCALAR_OFFSET + 2],
            l1_base_fee_scalar_bytes[L1_BLOB_BASE_FEE_SCALAR_OFFSET + 3],
        ]);

        self.l1_base_fee_scalar_word.assign(
            region,
            offset,
            Some((l1_base_fee_scalar as u64).to_le_bytes()),
        )?;
        self.l1_blob_base_fee_scalar_word.assign(
            region,
            offset,
            Some((l1_blob_base_fee_scalar as u64).to_le_bytes()),
        )?;
        let (tx_l1_fee, remainder) = (eth_types::Word::from(tx.rollup_data_gas_cost)
            * (block.l1_fee.base_fee
                * eth_types::Word::from(16)
                * eth_types::Word::from(l1_base_fee_scalar)
                + block.l1_fee.blob_base_fee * eth_types::Word::from(l1_blob_base_fee_scalar)))
        .div_mod(*ECOTONE_COST_DENOMINATOR);
        self.remainder_word
            .assign(region, offset, Some((remainder.as_u64()).to_le_bytes()))?;

        self.lt.assign_value(
            region,
            offset,
            Value::known(F::from(ECOTONE_COST_DENOMINATOR.as_u64())),
            Value::known(F::from(remainder.as_u64())),
        )?;

        self.proposer_reward_vault.assign(
            region,
            offset,
            Value::known(
                PROPOSER_REWARD_VAULT
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;
        self.proposer_reward.assign(
            region,
            offset,
            proposer_reward_vault_balance_balance_prev,
            vec![tx_l1_fee],
            proposer_reward_vault_balance,
        )?;

        Ok(())
    }
}
