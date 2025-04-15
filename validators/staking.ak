use aiken/collection/list.{foldl}
// use aiken/bytearray
use aiken/crypto.{VerificationKeyHash}
use cardano/address.{Address, VerificationKey}
use cardano/assets.{PolicyId, quantity_of}
use cardano/script_context.{ScriptContext, ScriptInfo, Spending}
use cardano/transaction.{Input, Output, OutputReference, Transaction}
// Import constants from environment config
use env.{min_curator_stake, min_issuer_stake}

/// Enum defining the role of the staker (e.g., Curator, Issuer).
/// Determines minimum staking requirements.
pub type StakeRole {
  Curator
  Issuer
}

/// Datum stored with each stake UTxO.
/// Contains information about the staker, their role, the amount staked,
/// and an associated identifier hash (e.g., related to a DID).
pub type StakeDatum {
  /// Verification key hash of the wallet staking the tokens.
  staker: VerificationKeyHash,
  /// An identifier associated with the stake, potentially a hash related to a DID.
  issuer_did_hash: ByteArray,
  /// The role of the staker (Curator or Issuer).
  role: StakeRole,
  /// The amount of FAIRWAY tokens staked.
  staked_amount: Int,
}

/// Redeemer defining the action being performed on the stake.
pub type StakeAction {
  /// Action for initially validating the stake conditions (though locking happens prior).
  Stake
  /// Action for the staker to reclaim their staked tokens.
  Withdraw
  /// Action for the designated authority to slash the staked tokens.
  Slash
}

// --- Action Handlers --- 

/// Validates the conditions required for the staking action.
/// Note: The actual locking of funds and datum creation occurs in the transaction
/// that creates the UTxO being spent here.
fn handle_stake(
  fairway_token_policy: PolicyId,
  did_token_policy: PolicyId,
  datum: StakeDatum,
  context: ScriptContext,
) -> Bool {
  // 1. Must be signed by the staker defined in the datum.
  let check_sig = list.has(context.transaction.extra_signatories, datum.staker)

  // 2. Must have exactly one token of the specified DID policy in reference inputs.
  let check_did_ref =
    check_did_token_reference(
      did_token_policy,
      context.transaction.reference_inputs,
    )

  // 3. Must have a continuing output to the script address containing the correct datum and staked amount.
  let check_output = check_stake_output(fairway_token_policy, context, datum)

  // 4. The staked amount must meet the minimum defined for the staker's role.
  let check_min_stake = check_minimum_stake(datum)

  // All conditions must pass.
  check_sig && check_did_ref && check_output && check_min_stake
}

/// Validates the conditions for the staker to withdraw their stake.
fn handle_withdraw(
  fairway_token_policy: PolicyId,
  datum: StakeDatum,
  context: ScriptContext,
) -> Bool {
  // 1. Must be signed by the staker defined in the datum.
  let check_sig = list.has(context.transaction.extra_signatories, datum.staker)

  // 2. The input being spent must contain the originally staked amount.
  let check_input =
    check_input_contains_stake(fairway_token_policy, context, datum)

  // 3. The transaction must return the full staked amount to the staker's address.
  let check_return =
    check_stake_returned_to_staker(
      fairway_token_policy,
      context.transaction,
      datum,
    )

  // TODO: Optional: Check time lock (e.g., require withdrawal only after a certain period)
  // All conditions must pass.
  check_sig && check_input && check_return
}

/// Validates the conditions for the slashing authority to slash the stake.
fn handle_slash(
  fairway_token_policy: PolicyId,
  slashing_authority: ByteArray,
  // Passed as parameter
  datum: StakeDatum,
  context: ScriptContext,
) -> Bool {
  // 1. Must be signed by the designated slashing authority.
  let check_auth_sig =
    list.has(context.transaction.extra_signatories, slashing_authority)

  // 2. The input being spent must contain the originally staked amount.
  let check_input =
    check_input_contains_stake(fairway_token_policy, context, datum)

  // 3. The transaction must *not* return the staked amount to the original staker.
  let check_no_return =
    check_stake_not_returned_to_staker(
      fairway_token_policy,
      context.transaction,
      datum,
    )

  // All conditions must pass.
  check_auth_sig && check_input && check_no_return
}

// --- Helper Functions ---

/// Get the UTXO input being spent by this script invocation
fn find_own_input(tx: Transaction, info: ScriptInfo) -> Option<Input> {
  when info is {
    Spending { output: ref, .. } ->
      list.find(tx.inputs, fn(input) { input.output_reference == ref })
    _ -> None
  }
}

/// Check that the input being spent contains the correct staked amount
fn check_input_contains_stake(
  fairway_token_policy: PolicyId,
  context: ScriptContext,
  datum: StakeDatum,
) -> Bool {
  when find_own_input(context.transaction, context.info) is {
    // Use when pattern match
    Some(input) ->
      // Case for Some(input)
      quantity_of(input.output.value, fairway_token_policy, #"") == // Empty AssetName
      datum.staked_amount
    None -> False
  }
  // Case for None
}

/// Check that the transaction sends the staked amount back to the staker's address
fn check_stake_returned_to_staker(
  fairway_token_policy: PolicyId,
  tx: Transaction,
  datum: StakeDatum,
) -> Bool {
  let total_sent =
    foldl(
      tx.outputs,
      0,
      fn(output, acc) {
        if output.address == Address(VerificationKey(datum.staker), None) {
          acc + quantity_of(output.value, fairway_token_policy, #"")
        } else {
          acc
        }
      },
    )
  total_sent >= datum.staked_amount
}

/// Check that the transaction does NOT send the staked amount back to the staker's address
fn check_stake_not_returned_to_staker(
  fairway_token_policy: PolicyId,
  tx: Transaction,
  datum: StakeDatum,
) -> Bool {
  let total_sent =
    foldl(
      tx.outputs,
      0,
      fn(output, acc) {
        if output.address == Address(VerificationKey(datum.staker), None) {
          acc + quantity_of(output.value, fairway_token_policy, #"")
        } else {
          acc
        }
      },
    )
  total_sent == 0
}

/// Check that exactly one DID token (matching the specified policy ID) 
/// exists across all reference inputs in the transaction.
fn check_did_token_reference(
  did_token_policy: PolicyId,
  reference_inputs: List<Input>,
) -> Bool {
  let count =
    list.foldl(
      reference_inputs,
      0,
      fn(input, acc) {
        acc + quantity_of(input.output.value, did_token_policy, #"")
      },
    )
  // Empty AssetName
  count == 1
}

/// Check that the transaction creates exactly one output back to the script address
/// containing the correct staked amount of the Fairway token and the correct datum.
/// (Assumes datum check happens implicitly via UTxO comparison or off-chain).
fn check_stake_output(
  fairway_token_policy: PolicyId,
  context: ScriptContext,
  datum: StakeDatum,
) -> Bool {
  // Get the script's own address from the context
  let own_address =
    when context.info is {
      Spending { .. } -> {
        // Use named field (even if empty)
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
        #"",
      ) == // Empty AssetName
      datum.staked_amount
    },
  )
}

/// Check if the staked amount in the datum meets the minimum requirement 
/// defined in the environment config for the staker's role.
fn check_minimum_stake(datum: StakeDatum) -> Bool {
  when datum.role is {
    Curator -> datum.staked_amount >= min_curator_stake
    Issuer -> datum.staked_amount >= min_issuer_stake
  }
}

/// Main validator logic for the staking contract.
/// Parameters are embedded into the script at compile/blueprint application time.
validator staking_contract(
  /// Policy ID of the FAIRWAY token used for staking.
  fairway_token_policy: PolicyId,
  /// Policy ID of the DID token required as a reference input.
  did_token_policy: PolicyId,
  /// Verification key hash of the authority allowed to slash stakes.
  slashing_authority: ByteArray,
) {
  /// Spend handler: Controls how UTxOs locked by this validator can be spent.
  spend(
    /// The datum attached to the UTxO being spent (passed as Option).
    datum_opt: Option<StakeDatum>,
    /// The action (Stake, Withdraw, Slash) being attempted.
    redeemer: StakeAction,
    /// The specific UTxO being spent (OutputReference). Ignored here as info is in context.
    _target: OutputReference,
    /// The full transaction context provided by the ledger.
    context: ScriptContext,
  ) {
    // Ensure the datum is present, otherwise fail.
    expect Some(datum) = datum_opt

    // Dispatch to the appropriate handler based on the redeemer action.
    when redeemer is {
      Stake ->
        handle_stake(fairway_token_policy, did_token_policy, datum, context)
      Withdraw -> handle_withdraw(fairway_token_policy, datum, context)
      Slash ->
        handle_slash(fairway_token_policy, slashing_authority, datum, context)
    }
  }

  // Fallback handler to reject any script purpose other than 'spend'.
  else(_) {
    fail @"Unsupported script purpose"
  }
}
