# Munchables

[A web3 point farming game](https://code4rena.com/audits/2024-05-munchables) in which Keepers nurture creatures to help them evolve, deploying strategies to earn them rewards in competition with other players.

## Audit Findings Summary

| ID | Title | Severity |
|----|----------|----------|
| [H-1](#h-1-operatordelegatorcompletewithdrawals-will-revert-when-token-is-not-native-eth-causing-blockage-of-manual-withdrawals-via-eigenlayer) | `OperatorDelegator::completeWithdrawals` will revert when token is not native ETH, causing blockage of manual withdrawals via `EigenLayer` | High |
| [H-2](#h-2-minting-ezeth-does-not-account-for-tokens-queued-for-withdrawal-via-withdrawqueuewithdraw) | Minting `ezETH` does not account for tokens queued for withdrawal via `WithdrawQueue::withdraw` | High |
| [M-1](#m-1-deposit-and-withdraw-should-have-slippage-protection) | `deposit` and `withdraw` should have slippage protection | Medium |
---

## [H-1] Users can change their `unlockTime` to unlock tokens earlier, breaking protocol invariant

# Vulnerability details

## Impact
`LockManager` allows users to lock tokens in return for `rewards`. They can unlock their tokens once their respective `unlockTime` has passed.

`setLockDuration()` allows users to update their `lockDuration`, which will also update their `unlockTime`. Users are only allowed to specify a `lockDuration` that extends their `unlockTime`, not one that reduces it.

However, the `unlockTime` is incorrectly updated from the `lastLockTime`, rather than from the current `unlockTime`. This allows a user to reduce their `unlockTime`, breaking a protocol invariant.

## Proof of Concept
When users lock their tokens, the following values are set:

[LockManager.sol#L381-L384](https://github.com/code-423n4/2024-05-munchables/blob/main/src/managers/LockManager.sol#L381-L384)
```javascript
lockedToken.lastLockTime = uint32(block.timestamp);
lockedToken.unlockTime = uint32(block.timestamp) + uint32(_lockDuration);
```

After the `unlockTime` has passed, users can unlock their tokens and receive rewards.

During their `lock period`, users can update their `unlockTime` by calling `setLockDuration()` with a new `lockDuration`

[LockManager.sol#L256-L269](https://github.com/code-423n4/2024-05-munchables/blob/main/src/managers/LockManager.sol#L256-L269)
```javascript
if (lockedTokens[msg.sender][tokenContract].quantity > 0) {
    // check they are not setting lock time before current unlocktime
    if (
        uint32(block.timestamp) + uint32(_duration) <
        lockedTokens[msg.sender][tokenContract].unlockTime
    ) {
        revert LockDurationReducedError();
    }

    uint32 lastLockTime = lockedTokens[msg.sender][tokenContract]
        .lastLockTime;
    lockedTokens[msg.sender][tokenContract].unlockTime =
        lastLockTime +
        uint32(_duration);
}
```

We revert if `uint32(block.timestamp) + uint32(_duration) < lockedTokens[msg.sender][tokenContract].unlockTime` (where `_duration` is the new duration), because a protocol invariant is that users cannot reduce their `unlockTime`.

The `unlockTime` is updated to `lastLockTime + uint32(_duration)`.

Consider the following example:

Alice locks her tokens by calling `lock()` with the initial `_lockDuration` of 10 days. `lastLockTime` is set to the current `block.timestamp` and `unlockTime` is set to `block.timestamp + 10 days`.

Now, let's assume `5 days` have passed since she has locked.

Alice calls `setLockDuration()` with the new `_duration` as `6 days`. The `uint32(block.timestamp) + uint32(_duration) < lockedTokens[msg.sender][tokenContract].unlockTime` check will not execute because 6 days from the current `block.timestamp` will be `11 days` from the `original lock time` (since `5 days` have already passed). This is greater than the `unlockTime`, which is `10 days` from the `original lock time`.

To put it more simply:

`uint32(block.timestamp) + uint32(_duration)` = 6 days from now, which is 11 days after the initial lock (since 5 days have passed).

`lockedTokens[msg.sender][tokenContract].unlockTime` = 5 days from now, since it was set to 10 days after the initial lock.

So `uint32(block.timestamp) + uint32(_duration) < lockedTokens[msg.sender][tokenContract].unlockTime` is false, and the `unlockTime` will be updated.

Recall that `lastLockTime` is the time when Alice originally locked her tokens.

So the new `unlockTime` is set to `lastLockTime + uint32(_duration)`, which is `6 days` from the original lock date. Alice will now be able to unlock her tokens 6 days from the original lock time (which is 1 day from now, since 5 days have already passed), when she should have only been able to unlock her tokens after `10 days`.

In this case, she bypassed the protocol invariant where users cannot reduce lock duration.

## Tools Used
Manual Review.

## Recommended Mitigation Steps
Update the new `_duration` from the `unlockTime`, rather than from the original lock time `lastLockTime`. Considering the above example, if Alice now specifies `6 days` as the new `lock duration`, it will not change the `unlock time` from `10 days` to `6 days` from the original time, but rather `6 more days` from the current `unlock time`, which is total of `16 days` from when she originally locked her tokens.

```diff
function setLockDuration(uint256 _duration) external notPaused {
    if (_duration > configStorage.getUint(StorageKey.MaxLockDuration))
        revert MaximumLockDurationError();

    playerSettings[msg.sender].lockDuration = uint32(_duration);
    // update any existing lock
    uint256 configuredTokensLength = configuredTokenContracts.length;
    for (uint256 i; i < configuredTokensLength; i++) {
        address tokenContract = configuredTokenContracts[i];
        if (lockedTokens[msg.sender][tokenContract].quantity > 0) {
            // check they are not setting lock time before current unlocktime
            if (
                uint32(block.timestamp) + uint32(_duration) <
                lockedTokens[msg.sender][tokenContract].unlockTime
            ) {
                revert LockDurationReducedError();
            }

-               uint32 lastLockTime = lockedTokens[msg.sender][tokenContract]
-                   .lastLockTime;
-               lockedTokens[msg.sender][tokenContract].unlockTime =
-                   lastLockTime +
-                   uint32(_duration);

+               lockedTokens[msg.sender][tokenContract].unlockTime += _duration;

        }
    }

    emit LockDuration(msg.sender, _duration);
}
```

## [M-1] Proposers who disapproved USD price can still approve the same USD price, breaking protocol invariant

## Impact
`LockManager` allows users to lock tokens in return for `rewards`. They can unlock their tokens once their respective `unlockTime` has passed.

When users unlock their tokens, `AccountManager::forceHarvest()` is called, which gives users reward based off the `USD` value of their locked tokens.

This `USD` value can be changed at anytime by a `proposer` with `Pricefeed` role via a call to `proposeUSDPrice()`.

If enough `Pricefeed` roles approve the new `USD` value, that value will then be updated.

`Pricefeed` roles can also disapprove the proposed `USD` value. If enough disapprove, then the proposal will be rejected.

There is a check in place to ensure that if a `Pricefeed` role has already approved a proposal, then they cannot disapprove it.

However, this invariant can be broken by disapproving first and then proceeding to approve the same proposal.

## Proof of Concept
When an address with `Pricefeed` role disapproves a proposed `USD` value, there is a check to see if they already approved

[LockManager.sol#L225-L226](https://github.com/code-423n4/2024-05-munchables/blob/main/src/managers/LockManager.sol#L225-L226)
```javascript
if (usdUpdateProposal.approvals[msg.sender] == _usdProposalId)
revert ProposalAlreadyApprovedError();
```

This is to ensure that when a proposal is approved by a `Pricefeed` role, the same address cannot disapprove the same proposal. This is an invariant where the same msg.sender cannot approve and disapprove the same proposal.

However, when approving, there is no check to see if the `Pricefeed` role has already disapproved the proposal.

[#L191-L197](https://github.com/code-423n4/2024-05-munchables/blob/main/src/managers/LockManager.sol#L191-L197)
```javascript
if (usdUpdateProposal.proposer == address(0)) revert NoProposalError();
if (usdUpdateProposal.proposer == msg.sender)
    revert ProposerCannotApproveError();
if (usdUpdateProposal.approvals[msg.sender] == _usdProposalId)
    revert ProposalAlreadyApprovedError();
if (usdUpdateProposal.proposedPrice != _price)
    revert ProposalPriceNotMatchedError();
```

The same `Pricefeed` role can approve a proposal they already disapproved, breaking a protocol invariant.

## Tools Used
Manual Review.

## Recommended Mitigation Steps
Upon approval, revert if the caller had already disapproved the proposal:

```diff
function approveUSDPrice(
    uint256 _price
)
    external
    onlyOneOfRoles(
        [
            Role.PriceFeed_1,
            Role.PriceFeed_2,
            Role.PriceFeed_3,
            Role.PriceFeed_4,
            Role.PriceFeed_5
        ]
    )
{
    if (usdUpdateProposal.proposer == address(0)) revert NoProposalError();
    if (usdUpdateProposal.proposer == msg.sender)
        revert ProposerCannotApproveError();
    if (usdUpdateProposal.approvals[msg.sender] == _usdProposalId)
        revert ProposalAlreadyApprovedError();
+       if (usdUpdateProposal.disapprovals[msg.sender] == _usdProposalId)
+           revert ProposalAlreadyDisapprovedError();
    if (usdUpdateProposal.proposedPrice != _price)
        revert ProposalPriceNotMatchedError();

    usdUpdateProposal.approvals[msg.sender] = _usdProposalId;
    usdUpdateProposal.approvalsCount++;

    if (usdUpdateProposal.approvalsCount >= APPROVE_THRESHOLD) {
        _execUSDPriceUpdate();
    }

    emit ApprovedUSDPrice(msg.sender);
}
```
