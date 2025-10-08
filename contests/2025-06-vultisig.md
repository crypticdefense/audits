# Vultisig

[The secure](https://code4rena.com/audits/2024-06-vultisig), seedless crypto wallet & vault for everyone.

## Audit Findings Summary

| ID | Title | Severity |
|----|----------|----------|
| [M-1](#m-1-ilopoolclaim-incorrectly-re-adds-fees-to-the-callers-rewards-which-can-cause-users-to-receive-rewards-owed-to-others-or-dos-due-to-underflow) | `ILOPool::claim` incorrectly re-adds fees to the caller's rewards, which can cause users to receive rewards owed to others, or DoS due to underflow | Medium |
| [M-2](#m-2-ilopoolclaim-should-have-slippage-protection) | `ILOPool::claim` should have slippage protection | Medium |
---

## [M-1] `ILOPool::claim` incorrectly re-adds fees to the caller's rewards, which can cause users to receive rewards owed to others, or DoS due to underflow

# Vulnerability details

## Impact
Project admins can create multiple `ILOPools` for their project, which contains mechanism such as vesting, sale management, ERC721 integration, etc.

Users can earn rewards for the amount they invested by calling `ILOPool::claim()`. These rewards are calculated based off the `liquidity2claim`, which is the `amount of unlocked liquidity for the position`.

`IUniswapV3PoolActions::burn()` is called with the `liquidity2claim` amount, which burns the liquidity and returns tokens owed for the liquidity to the position, `amount0` and `amount1`, which represent the `RAISE_TOKEN` and `SALE_TOKEN`.

A call to `IUniswapV3PoolActions::collect()` must be made to actually receive these tokens owed.

After burning the liquidity and before the call to collect(), the protocol calculates fees owed to the project: `platform fee` and `performance fee`. These fees must be deducted from the `amount0` and `amount1` from the `burn()` call.

The problem is that the protocol assumes these fees are not included in the `amount0` and `amount1` accounting, and proceeds to add them (minus the amount owed to project) to the `amount0` and `amount1` owed to the caller.

Due to this error in accounting, the user will receive extra rewards from the `ILOPool`, or DoS may occur due to underflow/insufficient funds.

## Proof of Concept
[ILOPool.sol#L204-L205](https://github.com/code-423n4/2024-06-vultisig/blob/main/src/ILOPool.sol#L204-L205)
```javascript
// get amount of token0 and token1 that pool will return for us
(amount0, amount1) = pool.burn(TICK_LOWER, TICK_UPPER, liquidity2Claim);
```

The claimable liquidity is burned from the pool and the amount of tokens earned is returned. This amount includes the fees owed to the position as observered [here](https://github.com/Uniswap/v3-core/blob/main/contracts/UniswapV3Pool.sol#L379).

Once the liquidity is burned, `platform fees` are deducted from the amounts returned.

[ILOPool.sol#L207-L208](https://github.com/code-423n4/2024-06-vultisig/blob/main/src/ILOPool.sol#L207-L208)
```javascript
// get amount of token0 and token1 after deduct platform fee
(amount0, amount1) = _deductFees(amount0, amount1, _project.platformFee);
```

The performance fee is also calculated.

[ILOPool.sol#L212-L227)](https://github.com/code-423n4/2024-06-vultisig/blob/main/src/ILOPool.sol#L212-L227)
```javascript
    // calculate amount of fees that position generated
    (, uint256 feeGrowthInside0LastX128, uint256 feeGrowthInside1LastX128, , ) = pool.positions(positionKey);
    uint256 fees0 = FullMath.mulDiv(
                        feeGrowthInside0LastX128 - position.feeGrowthInside0LastX128,
                        positionLiquidity,
                        FixedPoint128.Q128
                    );

    uint256 fees1 = FullMath.mulDiv(
                        feeGrowthInside1LastX128 - position.feeGrowthInside1LastX128,
                        positionLiquidity,
                        FixedPoint128.Q128
                    );

    // amount of fees after deduct performance fee
    (fees0, fees1) = _deductFees(fees0, fees1, _project.performanceFee);
```

This calculates the amount of fees of the position since the last claim. From this amount, the fees are deducted to allocate funds for the `performance fee`.

The problem is, these fees are added again to `amount0` and `amount1`:

[ILOPool.sol#L229-L231](https://github.com/code-423n4/2024-06-vultisig/blob/main/src/ILOPool.sol#L229-L231)
```javascript
// fees is combined with liquidity token amount to return to the user
amount0 += fees0;
amount1 += fees1;
```

Here is where the problem lies, this fee amount is already included in `amount0` and `amount1`, and we are adding it again. The correct solution is to subtract it instead.

Consider the following example, these values may seem unrealistic but they are used for simplicity:

`amount0, amount1 = 20e18`

`fees0, fees1 before deducted fees = 10e18`

Assume 20% goes to the project performance fee.

`fees0, fees1 after deducted fees = 8e18`.

Now `amount0, amount1 = 20e18 + 8e18 = 28e18`.

Since the fees were already included in the initial `amount0, amount1`, this adds extra tokens to the user's amount.

The tokens are then collected:

[ILOPool.sol#L241-L248](https://github.com/code-423n4/2024-06-vultisig/blob/main/src/ILOPool.sol#L241-L248)
```javascript
// real amount collected from uintswap pool
(uint128 amountCollected0, uint128 amountCollected1) = pool.collect(
    address(this),
    TICK_LOWER,
    TICK_UPPER,
    type(uint128).max,
    type(uint128).max
);
```

The values returned here from the `collect()` call are the same values returned from the `burn()` call. In other words, `amountCollected0` and `amountCollected1` are our initial `amount0` and `amount1` when `burn()` was first called, before deducting the fees.

[ILOPool.sol#L251-L260](https://github.com/code-423n4/2024-06-vultisig/blob/main/src/ILOPool.sol#L251-L260)
```javascript
// transfer token for user
@>  TransferHelper.safeTransfer(_cachedPoolKey.token0, ownerOf(tokenId), amount0);
@>  TransferHelper.safeTransfer(_cachedPoolKey.token1, ownerOf(tokenId), amount1);

emit Claim(ownerOf(tokenId), tokenId,liquidity2Claim, amount0, amount1, position.feeGrowthInside0LastX128, position.feeGrowthInside1LastX128);

address feeTaker = IILOManager(MANAGER).FEE_TAKER();
// transfer fee to fee taker
@>  TransferHelper.safeTransfer(_cachedPoolKey.token0, feeTaker, amountCollected0-amount0);
@>  TransferHelper.safeTransfer(_cachedPoolKey.token1, feeTaker, amountCollected1-amount1);
```

As we can see, the user will receive extra tokens from the `ILOPool`, effectively taking tokens from others. If there isn't enough tokens, the call will revert, causing DoS.

In addition, since `amount0` and `amount1` are increased, the `feeTaker` will receive less tokens. If these amounts happen to be greater than `amountCollected`, it will underflow and cause DoS.

## Tools Used
Manual review.

## Recommended Mitigation Steps
Consider the following changes when deducting the performance fees. Since fees0 and fees1 are already included in amount0 and amount1, calculate the amount of fees the user should keep by calling `_deductFees`, then remove the amount that is owed to the fee collector, by deducting the amount owed to the user from the original amount.

```diff
// calculate amount of fees that position generated
(, uint256 feeGrowthInside0LastX128, uint256 feeGrowthInside1LastX128, , ) = pool.positions(positionKey);
uint256 fees0 = FullMath.mulDiv(
                    feeGrowthInside0LastX128 - position.feeGrowthInside0LastX128,
                    positionLiquidity,
                    FixedPoint128.Q128
                );

uint256 fees1 = FullMath.mulDiv(
                    feeGrowthInside1LastX128 - position.feeGrowthInside1LastX128,
                    positionLiquidity,
                    FixedPoint128.Q128
                );

// amount of fees after deduct performance fee
-   (fees0, fees1) = _deductFees(fees0, fees1, _project.performanceFee);
+   uint256 performanceFee0;
+   uint256 performanceFee1;
+   (performanceFee0, performanceFee1) = _deductFees(fees0, fees1, _project.performanceFee);

// fees is combined with liquidity token amount to return to the user
-   amount0 += fees0;
-   amount1 += fees1;
+   amount0 -= (fees0 - performanceFee0);
+   amount1 -= (fees1 - performanceFee1);
```

## [M-2] `ILOPool::claim` should have slippage protection

# Vulnerability details

## Impact
`ILOPool::buy` allows whitelisted recipients to invest in a project and mints an NFT of their position corresponding to liquidity amount for the amount of `raise tokens` they transferred.

`ILOPool::claim` allows users to claim tokens associated with their position ID, and returns the amounts of token0 and token1 that were collected for the position represented by the position (token) ID.

This is done by calling external `burn()` and `collect()` functions of the `Uniswap v3 pool`. The problem is the amount they receive may change prior to execution (i.e, while it's in the mempool), which can cause users to receive much less amount than they are owed.

## Proof of Concept
[ILOPool.sol#L205)](https://github.com/code-423n4/2024-06-vultisig/blob/main/src/ILOPool.sol#L205)
```javascript
// get amount of token0 and token1 that pool will return for us
(amount0, amount1) = pool.burn(TICK_LOWER, TICK_UPPER, liquidity2Claim);
```

The external `Uniswap v3 pool` is called with the amount of liquidity the caller is eligible to claim, and this amount is burned. The caller is returned the amount of tokens received from the burn.

When the external burn call is executed, to calculate the amount of tokens the caller will receive, the following is executed from the `Uniswap V3 pool`

[UniswapV3Pool.sol#L336-L359](https://github.com/Uniswap/v3-core/blob/main/contracts/UniswapV3Pool.sol#L336-L359)
```javascript
} else if (_slot0.tick < params.tickUpper) {
    // current tick is inside the passed range
    uint128 liquidityBefore = liquidity; // SLOAD for gas optimization

    // write an oracle entry
    (slot0.observationIndex, slot0.observationCardinality) = observations.write(
        _slot0.observationIndex,
        _blockTimestamp(),
        _slot0.tick,
        liquidityBefore,
        _slot0.observationCardinality,
        _slot0.observationCardinalityNext
    );

    amount0 = SqrtPriceMath.getAmount0Delta(
        _slot0.sqrtPriceX96,
        TickMath.getSqrtRatioAtTick(params.tickUpper),
        params.liquidityDelta
    );
    amount1 = SqrtPriceMath.getAmount1Delta(
        TickMath.getSqrtRatioAtTick(params.tickLower),
        _slot0.sqrtPriceX96,
        params.liquidityDelta
    );
```

These values can change prior to execution, another user may also front-run to claim before, potentially causing the caller to receive less tokens.

## Tools Used
Manual review

## Recommended Mitigation Steps
Incorporate slippage protection in `ILOPool::claim`
