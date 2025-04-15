// use aiken/bytearray
use aiken/crypto.{VerificationKeyHash}
use aiken/collection/list.{foldl}
use cardano/transaction.{Input, Output, Transaction, OutputReference}
use cardano/address.{Address, VerificationKey}
use cardano/script_context.{ScriptContext, ScriptInfo, Spending}
use cardano/assets.{PolicyId, quantity_of}

// Import constants from environment config
use env.{min_curator_stake, min_issuer_stake}

// Define constants directly in this file for debugging
// pub const FAIRWAY_TOKEN_POLICY: ByteArray = #"00000000000000000000000000000000000000000000000000000000"
// pub const DID_TOKEN_POLICY: ByteArray = #"00000000000000000000000000000000000000000000000000000000"
// // This should be the Blake2b-224 hash of the verification key
// pub const SLASHING_AUTHORITY_KEY_HASH: ByteArray = #"00000000000000000000000000000000000000000000000000000000"
// pub const MIN_CURATOR_STAKE: Int = 0
// pub const MIN_ISSUER_STAKE: Int = 0

// Import constants explicitly from the library module
// use fairway/staking/lib/config.{FAIRWAY_TOKEN_POLICY, DID_TOKEN_POLICY, SLASHING_AUTHORITY_KEY_HASH, MIN_CURATOR_STAKE, MIN_ISSUER_STAKE}

// Minimal type definitions for debugging
// pub opaque type StakeDatum { DummyDatum } 
// pub opaque type StakeAction { DummyAction }
// pub type ScriptContext { DummyContext }

/// Enum defining the role of the staker
pub type StakeRole {
  Curator
  Issuer
}

/// Datum stored with each stake UTXO
pub type StakeDatum {
  staker: VerificationKeyHash,
  issuer_did_hash: ByteArray,
  role: StakeRole,
  staked_amount: Int,
}

/// Redeemer defining the action being performed
pub type StakeAction {
  Stake
  Withdraw
  Slash
}

// Minimal validator for debugging
// validator spend(datum: StakeDatum, redeemer: StakeAction, context: ScriptContext) {
//   // Access the imported constant to ensure import works
//   let _unused = TEST_VALUE
//   True 
//   // when redeemer is {
//   //   Stake -> handle_stake(datum, context)
//   //   Withdraw -> handle_withdraw(datum, context)
//   //   Slash -> handle_slash(datum, context)
//   // }
// }

// --- Action Handlers --- 

fn handle_stake(fairway_token_policy: PolicyId, did_token_policy: PolicyId, datum: StakeDatum, context: ScriptContext) -> Bool {
  // Check staker signature (matches datum.staker)
  let check_sig = list.has(context.transaction.extra_signatories, datum.staker)

  // Check DID token reference input (policy DID_TOKEN_POLICY, count == 1)
  let check_did_ref = check_did_token_reference(did_token_policy, context.transaction.reference_inputs)

  // Check output to script contains datum.staked_amount of FAIRWAY_TOKEN
  let check_output = check_stake_output(fairway_token_policy, context, datum)

  // Check stake amount meets minimums based on datum.role
  let check_min_stake = check_minimum_stake(datum)

  check_sig && check_did_ref && check_output && check_min_stake
}

fn handle_withdraw(fairway_token_policy: PolicyId, datum: StakeDatum, context: ScriptContext) -> Bool {
  // Check staker signature (matches datum.staker)
  let check_sig = list.has(context.transaction.extra_signatories, datum.staker)

  // Check consumed input has datum.staked_amount of FAIRWAY_TOKEN
  let check_input = check_input_contains_stake(fairway_token_policy, context, datum)

  // Check transaction returns datum.staked_amount of FAIRWAY_TOKEN to datum.staker
  let check_return = check_stake_returned_to_staker(fairway_token_policy, context.transaction, datum)

  // TODO: Optional: Check time lock
  check_sig && check_input && check_return
}

fn handle_slash(fairway_token_policy: PolicyId, slashing_authority: ByteArray, datum: StakeDatum, context: ScriptContext) -> Bool {
  // Check slashing authority signature (SLASHING_AUTHORITY_KEY_HASH)
  let check_auth_sig = list.has(context.transaction.extra_signatories, slashing_authority)

  // Check consumed input has datum.staked_amount of FAIRWAY_TOKEN
  let check_input = check_input_contains_stake(fairway_token_policy, context, datum)

  // Check transaction does NOT return FAIRWAY_TOKEN to datum.staker
  let check_no_return = check_stake_not_returned_to_staker(fairway_token_policy, context.transaction, datum)

  check_auth_sig && check_input && check_no_return
}

// --- Helper Functions ---

/// Get the UTXO input being spent by this script invocation
fn find_own_input(tx: Transaction, info: ScriptInfo) -> Option<Input> {
  when info is {
    Spending { output: ref, .. } -> list.find(tx.inputs, fn(input) { input.output_reference == ref })
    _ -> None
  }
}

/// Check that the input being spent contains the correct staked amount
fn check_input_contains_stake(fairway_token_policy: PolicyId, context: ScriptContext, datum: StakeDatum) -> Bool {
  when find_own_input(context.transaction, context.info) is { // Use when pattern match
    Some(input) -> { // Case for Some(input)
      quantity_of(
        input.output.value,
        fairway_token_policy,
        #"", // Empty AssetName
      )
        == datum.staked_amount
    }
    None -> False // Case for None
  }
}

/// Check that the transaction sends the staked amount back to the staker
fn check_stake_returned_to_staker(fairway_token_policy: PolicyId, tx: Transaction, datum: StakeDatum) -> Bool {
  let total_sent = 
    foldl(
      tx.outputs,
      0,
      fn(output, acc) {
        if (output.address == Address(VerificationKey(datum.staker), None)) {
          acc + quantity_of(output.value, fairway_token_policy, #"")
        } else {
          acc
        }
      }
    )
  total_sent >= datum.staked_amount
}

/// Check that the transaction does NOT send the staked amount back to the staker
fn check_stake_not_returned_to_staker(fairway_token_policy: PolicyId, tx: Transaction, datum: StakeDatum) -> Bool {
  let total_sent = 
    foldl(
      tx.outputs,
      0,
      fn(output, acc) {
        if (output.address == Address(VerificationKey(datum.staker), None)) {
          acc + quantity_of(output.value, fairway_token_policy, #"")
        } else {
          acc
        }
      }
    )
  total_sent == 0
}

/// Check that exactly one DID token from the specified policy exists in reference inputs
fn check_did_token_reference(did_token_policy: PolicyId, reference_inputs: List<Input>) -> Bool {
  let count = list.foldl(
    reference_inputs,
    0,
    fn(input, acc) {
      acc
        + quantity_of(
            input.output.value,
            did_token_policy,
            #"", // Empty AssetName
          )
    },
  )
  count == 1
}

/// Check that the transaction creates an output to the script
/// containing the correct staked amount of the Fairway token.
fn check_stake_output(fairway_token_policy: PolicyId, context: ScriptContext, datum: StakeDatum) -> Bool {
  // Get the script's own address from the context
  let own_address = 
    when context.info is {
      Spending { .. } -> { // Use named field (even if empty)
        expect Some(input) = find_own_input(context.transaction, context.info)
        input.output.address 
      }
      _ -> fail @"Script must be used for Spending purpose" 
    }

  // Check if *any* output goes back to the script address with the correct amount
  list.any(
    context.transaction.outputs,
    fn(output) {
      // Check if output is to the script's address AND contains the correct amount
      output.address == own_address && quantity_of(
        output.value,
        fairway_token_policy,
        #"", // Empty AssetName
      ) == datum.staked_amount
    },
  )
}

/// Check if the staked amount meets the minimum requirement for the role
fn check_minimum_stake(datum: StakeDatum) -> Bool {
  when datum.role is {
    Curator -> datum.staked_amount >= min_curator_stake
    Issuer -> datum.staked_amount >= min_issuer_stake
  }
}

validator staking_contract(
  fairway_token_policy: PolicyId,
  did_token_policy: PolicyId,
  slashing_authority: ByteArray,
) {
  spend(datum_opt: Option<StakeDatum>, redeemer: StakeAction, _target: OutputReference, context: ScriptContext) {
    expect Some(datum) = datum_opt

    when redeemer is {
      Stake -> handle_stake(fairway_token_policy, did_token_policy, datum, context)
      Withdraw -> handle_withdraw(fairway_token_policy, datum, context)
      Slash -> handle_slash(fairway_token_policy, slashing_authority, datum, context)
    }
  }
  // --- Moved Action Handlers --- 
  // --- Moved Helper Functions --- 
} // Closing brace for validator block

// --- Action Handlers (commented out) ---
// 
// fun handle_stake(datum: StakeDatum, context: ScriptContext) -> Bool {
//    ...
// }
// ...
// 

// --- Action Handlers ---

// [This section is now empty as functions were moved]

// --- Helper Functions (commented out) ---
// 
// fun find_own_input(tx: Transaction, purpose: ScriptContext) -> Option<Input> {
//    ...
// }
// ...
// 

// --- Helper Functions ---

// [This section is now empty as functions were moved] 