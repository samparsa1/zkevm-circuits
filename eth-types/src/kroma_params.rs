//! Params for Kroma Network

use ethers_core::types::Address;
use lazy_static::lazy_static;

use crate::{address, Word};

lazy_static! {
  /// The caller address of a system transaction.
  pub static ref SYSTEM_TX_CALLER: Address = address!("0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001");

  /// The pre-deployed contract that stores the information to compute l1 rollup cost.
  pub static ref L1_BLOCK: Address = address!("0x4200000000000000000000000000000000000002");
  /// The pre-deployed contract that accumulates base fee.
  pub static ref PROTOCOL_VAULT: Address = address!("0x4200000000000000000000000000000000000006");
  /// The pre-deployed contract that accumulates l1 rollup cost.
  pub static ref PROPOSER_REWARD_VAULT: Address = address!("0x4200000000000000000000000000000000000007");
  /// The pre-deployed contract that accumulates proposer fee.
  pub static ref VALIDATOR_REWARD_VAULT: Address = address!("0x4200000000000000000000000000000000000008");

  /// The slot for basefee at L1Block.sol.
  pub static ref BASE_FEE_KEY: Word = Word::from(1);
  /// The slot for blobBaseFeeScalar and baseFeeScalar at L1Block.sol.
  pub static ref BASE_FEE_SCALAR_KEY: Word = Word::from(3);
  /// The slot for validatorRewardScalar at L1Block.sol.
  pub static ref VALIDATOR_REWARD_SCALAR_KEY: Word = Word::from(7);
  /// The slot for blobBaseFee at L1Block.sol.
  pub static ref BLOB_BASE_FEE_KEY: Word = Word::from(8);

  /// The denominator used to compute l1 rollup cost.
  pub static ref ECOTONE_COST_DENOMINATOR: Word = Word::from(1_000_000 * 16);
  /// Validator Reward Denominator
  pub static ref REWARD_DENOMINATOR: Word = Word::from(10000);
}
