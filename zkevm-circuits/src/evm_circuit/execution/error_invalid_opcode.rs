use crate::evm_circuit::{
    execution::ExecutionGadget,
    step::ExecutionState,
    table::{FixedTableTag, Lookup},
    util::{
        common_gadget::CommonErrorGadget, constraint_builder::ConstraintBuilder, CachedRegion, Cell,
    },
    witness::{Block, Call, ExecStep, Transaction},
};
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::{circuit::Value, plonk::Error};

/// Gadget for invalid opcodes. It verifies by a fixed lookup for
/// ResponsibleOpcode.
#[derive(Clone, Debug)]
pub(crate) struct ErrorInvalidOpcodeGadget<F> {
    opcode: Cell<F>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorInvalidOpcodeGadget<F> {
    const NAME: &'static str = "ErrorInvalidOpcode";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorInvalidOpcode;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.add_lookup(
            "Responsible opcode lookup",
            Lookup::Fixed {
                tag: FixedTableTag::ResponsibleOpcode.expr(),
                values: [
                    Self::EXECUTION_STATE.as_u64().expr(),
                    opcode.expr(),
                    0.expr(),
                ],
            },
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 2.expr());

        Self {
            opcode,
            common_error_gadget,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = F::from(step.opcode.unwrap().as_u64());
        self.opcode.assign(region, offset, Value::known(opcode))?;

        self.common_error_gadget
            .assign(region, offset, block, call, step, 2)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_bytes, test_util::CircuitTestBuilder};
    use eth_types::{bytecode, bytecode::Bytecode, ToWord, Word};
    use lazy_static::lazy_static;
    #[cfg(feature = "kroma")]
    use mock::test_ctx::helpers::{setup_kroma_required_accounts, system_deposit_tx};
    use mock::{
        test_ctx::{SimpleTestContext, TestContext3_1},
        tx_idx,
    };

    lazy_static! {
        static ref TESTING_INVALID_CODES: [Vec<u8>; 6] = [
            // Single invalid opcode
            vec![0x0e],
            vec![0x4f],
            vec![0xa5],
            vec![0xf6],
            vec![0xfe],
            // Multiple invalid opcodes
            vec![0x0c, 0x5e],
        ];
    }

    #[test]
    fn invalid_opcode_root() {
        for invalid_code in TESTING_INVALID_CODES.iter() {
            test_root_ok(invalid_code);
        }
    }

    #[test]
    fn invalid_opcode_internal() {
        for invalid_code in TESTING_INVALID_CODES.iter() {
            test_internal_ok(0x20, 0x00, invalid_code);
        }
    }

    fn test_root_ok(invalid_code: &[u8]) {
        let mut code = Bytecode::default();
        invalid_code.iter().for_each(|b| {
            code.write(*b, true);
        });

        CircuitTestBuilder::new_from_test_ctx(
            SimpleTestContext::simple_ctx_with_bytecode(code).unwrap(),
        )
        .run();
    }

    fn test_internal_ok(call_data_offset: usize, call_data_length: usize, invalid_code: &[u8]) {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // Code B gets called by code A, so the call is an internal call.
        let mut code_b = Bytecode::default();
        invalid_code.iter().for_each(|b| {
            code_b.write(*b, true);
        });

        // code A calls code B.
        let pushdata = rand_bytes(8);
        let code_a = bytecode! {
            // populate memory in A's context.
            PUSH8(Word::from_big_endian(&pushdata))
            PUSH1(0x00) // offset
            MSTORE
            // call ADDR_B.
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH32(call_data_length) // argsLength
            PUSH32(call_data_offset) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            PUSH32(0x1_0000) // gas
            CALL
            STOP
        };

        let ctx = TestContext3_1::new(
            None,
            |mut accs| {
                accs[0].address(addr_b).code(code_b);
                accs[1].address(addr_a).code(code_a);
                accs[2]
                    .address(mock::MOCK_ACCOUNTS[3])
                    .balance(Word::from(1_u64 << 20));
                #[cfg(feature = "kroma")]
                setup_kroma_required_accounts(accs.as_mut_slice(), 3);
            },
            |mut txs, accs| {
                #[cfg(feature = "kroma")]
                system_deposit_tx(txs[0]);
                txs[tx_idx!(0)].to(accs[1].address).from(accs[2].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
