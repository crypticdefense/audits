# PoolTogether

This audit is for the [PoolTogether](https://code4rena.com/audits/2024-03-pooltogether) V5 PrizeVault contract, factory and inherited contracts.

## Audit Findings Summary

| ID | Title | Severity |
|----|----------|----------|
| [H-1](#h-1-incorrect-yieldfeebalance-calculation) | Incorrect `yieldFeeBalance` calculation | High |
---

## [H-1] Incorrect `yieldFeeBalance` calculation

## Impact
`PrizeVault::claimYieldFeeShares` transfers yield fee shares to the yield fee recipient. However, it incorrectly resets the `yieldFeeBalance` to `0` on each call, causing any remaining `yieldFeeBalance` to be unclaimable indefinitely.

## Proof of Concept
`PrizeVault::claimYieldFeeShares` [#L611-622](https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L611-L622)

```javascript
function claimYieldFeeShares(uint256 _shares) external onlyYieldFeeRecipient {
    if (_shares == 0) revert MintZeroShares();

@>      uint256 _yieldFeeBalance = yieldFeeBalance;
    if (_shares > _yieldFeeBalance) revert SharesExceedsYieldFeeBalance(_shares, _yieldFeeBalance);

@>      yieldFeeBalance -= _yieldFeeBalance;

    _mint(msg.sender, _shares);

    emit ClaimYieldFeeShares(msg.sender, _shares);
}
```

In the function, you can see that the value of `yieldFeeBalance` is stored in `_yieldFeeBalance`, which is used to check if the number of shares entered exceeds the fees available to claim. However, we can see that `yieldFeeBalance` is then reduced by `_yieldFeeBalance`, effectively resetting it to 0. Any fee balance that was previously claimable now becomes unclaimable indefinitely.

This will cause issues if `_shares < yieldFeeBalance`. The correct way is to reduce `yieldFeeBalance` by `_shares`.

## Tools Used
Manual Review.

## Recommended Mitigation Steps
Perform the correct calculation:
