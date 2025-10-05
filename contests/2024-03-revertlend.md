# RevertLend

A [lending protocol](https://code4rena.com/audits/2024-03-revert-lend) specifically designed for liquidity providers on Uniswap v3.

## Audit Findings Summary

| ID | Title | Severity |
|----|----------|----------|
| [M-1](#m-1-v3vaultmaxredeem-does-not-comply-with-erc4626) | `V3Vault::maxRedeem` does not comply with ERC4626 | Medium |
| [M-2](#m-2-loss-of-funds-due-to-manipulation-of-slot0) | Loss of funds due to manipulation of `slot0` | Medium |
---

## [M-1] `V3Vault::maxRedeem` does not comply with ERC4626

# Vulnerability details

## Impact
`V3Vault::maxRedeem` does not follow ERC4626 EIP.

## Proof of Concept
The ERC4626 EIP states that `maxRedeem` ["MUST factor in both global and user-specific limits, like if redemption is entirely disabled (even temporarily) it MUST return 0."](https://eips.ethereum.org/EIPS/eip-4626#:~:text=MUST%20factor%20in%20both%20global%20and%20user%2Dspecific%20limits%2C%20like%20if%20redemption%20is%20entirely%20disabled%20(even%20temporarily)%20it%20MUST%20return%200.)

Looking at `V3Vault::maxRedeem`, it simply returns the balance of the owner address:

```javascript
/// @inheritdoc IERC4626
function maxRedeem(address owner) external view override returns (uint256) {
    return balanceOf(owner);
}
```

This implementation is incorrect because it is possible that redemption can be disabled. Looking at `V3Vault::redeem`:

```javascript
/// @inheritdoc IERC4626
function redeem(uint256 shares, address receiver, address owner) external override returns (uint256) {
    (uint256 assets,) = _withdraw(receiver, owner, shares, true);
    return assets;
}
```

Which makes a call to `_withdraw`:

```javascript
function _withdraw(address receiver, address owner, uint256 amount, bool isShare)
    internal
    returns (uint256 assets, uint256 shares)
{
    (uint256 newDebtExchangeRateX96, uint256 newLendExchangeRateX96) = _updateGlobalInterest();

    if (isShare) {
        shares = amount;
        assets = _convertToAssets(amount, newLendExchangeRateX96, Math.Rounding.Down);
    } else {
        assets = amount;
        shares = _convertToShares(amount, newLendExchangeRateX96, Math.Rounding.Up);
    }

    // if caller has allowance for owners shares - may call withdraw
    if (msg.sender != owner) {
        _spendAllowance(owner, msg.sender, shares);
    }

    (, uint256 available,) = _getAvailableBalance(newDebtExchangeRateX96, newLendExchangeRateX96);
@>      if (available < assets) {
        revert InsufficientLiquidity();
    }

    // fails if not enough shares
    _burn(owner, shares);
    SafeERC20.safeTransfer(IERC20(asset), receiver, assets);

    // when amounts are withdrawn - they may be deposited again
    dailyLendIncreaseLimitLeft += assets;

    emit Withdraw(msg.sender, receiver, owner, assets, shares);
}
```

Here, we can see that if the available assets are less than the assets calculated for redemption, then `redeem()` will revert due to insufficient liquidity. Therefore, redemption will be disabled if there is not enough liquidity available. `maxRedeem()` does not account for this (it must return 0 if redemption is disabled, even temporarily), thus does not follow ERC4626 standard.

## Tools Used
Manual Review

## Recommended Mitigation Steps
Deploy a check within `maxRedeem()` to return 0 if redemption is disabled due to insufficient liquidity:

```diff
function maxRedeem(address owner) external view override returns (uint256) {
+    (debtExchangeRateX96, lendExchangeRateX96) = _calculateGlobalInterest();   
+    uint256 assets = _convertToAssets(balanceOf(owner), lendExchangeRateX96, Math.Rounding.Down);
+    (, uint256 available,) = _getAvailableBalance(debtExchangeRateX96, lendExchangeRateX96);
+       if (available < assets) {
+           return 0;
+       }
    return balanceOf(owner);
}
```

## [M-2] Loss of funds due to manipulation of `slot0`

# Vulnerability details

## Impact
In multiple instances throughout the protocol, `pool.slot0` is used to calculate the `sqrtPriceX96` and `currentTick`.

The problem is that there is a known issue with `slot0`, where it can be easily manipulated through MEV bots and flashloans. If `slot0` is used for sensitive information, this can lead to vulnerabilities. In the case of the Revert Lend protocol, the `sqrtPriceX96` is used for calculating slippage when swapping in the `AutoRange.sol` and `AutoCompound.sol` contracts.

An attacker, by manipulating slot0, can sandwich attack the swaps and profit.

## Proof of Concept
Lets look at `Automater::_validateSwap`:

```javascript
function _validateSwap(
    bool swap0For1,
    uint256 amountIn,
    IUniswapV3Pool pool,
    uint32 twapPeriod,
    uint16 maxTickDifference,
    uint64 maxPriceDifferenceX64
) internal view returns (uint256 amountOutMin, int24 currentTick, uint160 sqrtPriceX96, uint256 priceX96) {
    // get current price and tick
@>      (sqrtPriceX96, currentTick,,,,,) = pool.slot0();

    // check if current tick not too far from TWAP
    if (!_hasMaxTWAPTickDifference(pool, twapPeriod, currentTick, maxTickDifference)) {
        revert TWAPCheckFailed();
    }

    // calculate min output price price and percentage
    priceX96 = FullMath.mulDiv(sqrtPriceX96, sqrtPriceX96, Q96);
    if (swap0For1) {
        amountOutMin = FullMath.mulDiv(amountIn * (Q64 - maxPriceDifferenceX64), priceX96, Q96 * Q64);
    } else {
        amountOutMin = FullMath.mulDiv(amountIn * (Q64 - maxPriceDifferenceX64), Q96, priceX96 * Q64);
    }
}
```

Here, we can see that `slot0` is used to get the `sqrtPriceX96` (current price) and `currentTick` (tick for TWAP check). The `sqrtPriceX96` is subsequently used to calculate the `amountOutMin`, which is one of the values returned.

Now let's look at `AutoExit::_execute` lines 162-169:

```javascript
        // checks if price in valid oracle range and calculates amountOutMin
@>          (state.amountOutMin,,,) = _validateSwap(
            !state.isAbove,
            state.swapAmount,
            state.pool,
            TWAPSeconds,
            maxTWAPTickDifference,
            state.isAbove ? config.token1SlippageX64 : config.token0SlippageX64
        );

        (state.amountInDelta, state.amountOutDelta) = _routerSwap(
            Swapper.RouterSwapParams(
                state.isAbove ? IERC20(state.token1) : IERC20(state.token0),
                state.isAbove ? IERC20(state.token0) : IERC20(state.token1),
                state.swapAmount,
@>                  state.amountOutMin,
                params.swapData
            )
        );
```

Here, the `Automater::_validateSwap` function is called to calculate the slippage for the swap. This is also done in the `AutoRange::execute` function:

```javascript
    // check oracle for swap
@>      (state.amountOutMin, state.currentTick,,) = _validateSwap(
        params.swap0To1,
        params.amountIn,
        state.pool,
        TWAPSeconds,
        maxTWAPTickDifference,
        params.swap0To1 ? config.token0SlippageX64 : config.token1SlippageX64
    );

    if (
        state.currentTick < state.tickLower - config.lowerTickLimit
            || state.currentTick >= state.tickUpper + config.upperTickLimit
    ) {
        int24 tickSpacing = _getTickSpacing(state.fee);
        int24 baseTick = state.currentTick - (((state.currentTick % tickSpacing) + tickSpacing) % tickSpacing);

        // check if new range same as old range
        if (
            baseTick + config.lowerTickDelta == state.tickLower
                && baseTick + config.upperTickDelta == state.tickUpper
        ) {
            revert SameRange();
        }

        (state.amountInDelta, state.amountOutDelta) = _routerSwap(
            Swapper.RouterSwapParams(
                params.swap0To1 ? IERC20(state.token0) : IERC20(state.token1),
                params.swap0To1 ? IERC20(state.token1) : IERC20(state.token0),
                params.amountIn,
@>                  state.amountOutMin,
                params.swapData
            )
        );
```

As mentioned, an attacker can manipulate the `sqrtPriceX96`, thus manipulating the slippage, and perform a sandwich attack (front-run) on the swaps. This will lead to a loss of funds for the protocol, and therefore users.

## Tools Used
Manual Review.

## Recommended Mitigation Steps
Avoid using `slot0` and instead use Uniswap TWAP.
