# Balancer V3

[Balancer](https://cantina.xyz/code/949ad7c5-ea14-427d-b10a-54e33cef921b/overview) is a decentralized automated market maker (AMM) protocol built on Ethereum with a clear focus on fungible and yield-bearing liquidity

## Audit Findings Summary

| ID | Title | Severity |
|----|----------|----------|
| [M-1](#m-1-compositeliquidityrouter-does-not-utilize-slippage-protection-for-proportional-addremove-liquidity-operations) | CompositeLiquidityRouter does not utilize slippage protection for proportional add/remove liquidity operations | Medium |
| [L-1](#l-1-executing-buffer-swap-via-batchrouter-by-paying-with-eth-will-always-dos) | Executing buffer swap via BatchRouter by paying with ETH will always DoS | Low |
| [L-2](#l-2-compositeliquidityrouter-does-not-handle-case-where-buffer-does-not-have-sufficient-wrappedunwrapped-amount) | CompositeLiquidityRouter does not handle case where buffer does not have sufficient wrapped/unwrapped amount | Low |
| [L-3](#l-3-vault-lacks-ability-to-enable-query-once-disabled) | Vault lacks ability to enable query once disabled | Low |
| [L-4](#l-4-inadequate-slippage-protection-for-initializebuffer-addliquiditytobuffer-removeliquidityfrombuffer-functions) | Inadequate slippage protection for initializeBuffer, addLiquidityToBuffer, removeLiquidityFromBuffer functions | Low |
| [L-5](#l-5-pools-can-dos-removeliquidityrecovery-breaking-protocol-invariant) | Pools can DoS removeLiquidityRecovery, breaking protocol invariant | Low |
| [I-1](#i-1-compositeliquidityrouter-does-not-support-wrapping-if-parentchild-pools-have-wrapped-token-and-its-corresponding-underlying) | CompositeLiquidityRouter does not support wrapping if parent/child pools have wrapped token and its corresponding underlying | Informational |
| [I-2](#i-2-vaultfactory-can-be-forced-to-revert) | VaultFactory can be forced to revert | Informational |
| [I-3](#i-3-removeliquidityrecovery-should-have-slippage-protection) | removeLiquidityRecovery should have slippage protection | Informational |
| [I-4](#i-4-avalanche-does-not-support-transient-storage) | Avalanche does not support transient storage | Informational |
| [I-5](#i-5-router-initialize-pool-may-fail-for-0-transfer-tokens) | Router initialize pool may fail for 0 transfer tokens | Informational |
---

## [M-1] CompositeLiquidityRouter does not utilize slippage protection for proportional add/remove liquidity operations

## Description

CompositeLiquidityRouter acts as the the entrypoint for add/remove liquidity operations on ERC4626 and nested pools.

The Balancer vault consists of ERC4626 Liquidity Buffers, which has two tokens: vault shares (wrapped token) and the vault asset (unwrapped token).

A huge incentive for buffers is that it's wrapped asset (ERC4626 shares) can be used as a token within pools. So a pool with ERC4626 wrapped token, and non ERC4626 tokens (i.e, DAI, USDC, WETH) can all exist in a single pool.

The CompositeLiquidityRouter facilitate add/remove liquidity operations for these pools. Proportional add/remove operations are where the exact amount of BPT (LP tokens) are specified by the caller to give/receive proportional amounts of liquidity across the pool.

Add proportional liquidity: User specifies exact bpt to be minted to them and maxAmountIn of tokens (slippage protection for tokens to put in the pool). bpt specified is used to calculate the actual liquidity amount to put in.

Remove proportional liquidity: User specifies exact bpt to burn, and minAmountOut of tokens to receive (slippage protection for tokens to be received). bpt specified is used to calculate the actual amount of liquidity out.

The problem is that the slippage protection specified by the user for these operations are not used on non-ERC4626 tokens (so for tokens like USDC, DAI). This means that the user can receive far less than the minimum they specified, or pay far more than the specified max amount in, which falls under High severity category: User granted approvals to router can be used by anyone, as their entire amount of approvals can be drained.

## Proof of Concept

Let's analyze CompositeLiquidityRouter::addLiquidityProportionalToERC4626Pool and CompositeLiquidityRouter::removeLiquidityProportionalFromERC4626Pool functions:

CompositeLiquidityRouter.sol#L74-L98
```javascript
/// @inheritdoc ICompositeLiquidityRouter
/**
* @notice Add proportional amounts of underlying tokens to an ERC4626 pool through the buffer.
* @dev An "ERC4626 pool" contains IERC4626 yield-bearing tokens (e.g., waDAI).
* @param pool Address of the liquidity pool
* @param maxUnderlyingAmountsIn Maximum amounts of underlying tokens in, sorted in token registration order of
* wrapped tokens in the pool
* @param exactBptAmountOut Exact amount of pool tokens to be received
* @param wethIsEth If true, incoming ETH will be wrapped to WETH and outgoing WETH will be unwrapped to ETH
* @param userData Additional (optional) data required for adding liquidity
* @return underlyingAmountsIn Actual amounts of tokens added, sorted in token registration order of wrapped tokens
* in the pool
*/
    function addLiquidityProportionalToERC4626Pool(
        address pool,
@>      uint256[] memory maxUnderlyingAmountsIn,
@>      uint256 exactBptAmountOut,
        bool wethIsEth,
        bytes memory userData
    ) external payable saveSender returns (uint256[] memory underlyingAmountsIn) {
        underlyingAmountsIn = abi.decode(
            _vault.unlock(
                abi.encodeCall(
                    CompositeLiquidityRouter.addLiquidityERC4626PoolProportionalHook,
                    AddLiquidityHookParams({
                        sender: msg.sender,
                        pool: pool,
                        maxAmountsIn: maxUnderlyingAmountsIn,
                        minBptAmountOut: exactBptAmountOut,
                        kind: AddLiquidityKind.PROPORTIONAL,
                        wethIsEth: wethIsEth,
                        userData: userData
                    })
                )
            ),
            (uint256[])
        );
    }
```
The caller specifies maxUnderlyingAmountsIn, where each index is the max amount of token to spend for each token in the pool, sorted in order.

Vault::unlock unlocks the vault, which executes a call-back to CompositeLiquidityRouter.addLiquidityERC4626PoolProportionalHook:

Vault.sol#L117-L119
```javascript
function unlock(bytes calldata data) external transient returns (bytes memory result) {
        return (msg.sender).functionCall(data);
    }
```
Vault will callback to the following function:

CompositeLiquidityRouter.sol#L227-L257
```javascript
function addLiquidityERC4626PoolProportionalHook(
        AddLiquidityHookParams calldata params
    ) external nonReentrant onlyVault returns (uint256[] memory underlyingAmountsIn) {
@>      IERC20[] memory erc4626PoolTokens = _vault.getPoolTokens(params.pool);
        uint256 poolTokensLength = erc4626PoolTokens.length;

        uint256[] memory maxAmounts = new uint256[](poolTokensLength);
@>      for (uint256 i = 0; i < poolTokensLength; ++i) {
            maxAmounts[i] = _MAX_AMOUNT; //@audit _MAX_AMOUNT = type(uint128).max,
        }

        // Add wrapped amounts to the ERC4626 pool.
        (uint256[] memory wrappedAmountsIn, , ) = _vault.addLiquidity(
            AddLiquidityParams({
                pool: params.pool,
                to: params.sender,
@>              maxAmountsIn: maxAmounts, //@audit each element here is type(uint128).max, acting as no slippage
@>              minBptAmountOut: params.minBptAmountOut, //@audit exact amount of bptIn
                kind: params.kind,
                userData: params.userData
            })
        );

@>      (underlyingAmountsIn, ) = _wrapTokens( //@audit slippage specified by user should be checked here
            params,
            erc4626PoolTokens,
            wrappedAmountsIn,
            SwapKind.EXACT_OUT,
            params.maxAmountsIn //@audit this is the original slippage specified by the caller
        );
    }
```
Each pool token is retrieved via _vault.getPoolTokens(params.pool). Looping through the length of the pool tokens, each element of maxAmounts is set to _MAX_AMOUNT = type(uint128).max. Then, addLiquidity is executed with maxAmounts and exactBptIn. The maxAmounts here effectively act as 0 slippage during the addLiquidity call, but that is intentional and by-design. The intention here is to check for the actual slippage specified by the user during the _wrapTokens call. This is because at least one of the pool tokens may be in the form of ERC4626 wrapped token, and the slippage maxAmountIn specified by the user only reflects the unwrapped amount of that token. So to properly check slippage, the unwrapped amount must be calculated and then maxAmountIn should be checked. However, maxAmountIn should be checked for all other tokens as well, as the pool can contain non-ERC4626 tokens.

Looking at the call to _wrapTokens, I have added @audit tags to enhance readability:

CompositeLiquidityRouter.sol#L310-L372
```javascript
function _wrapTokens(
        AddLiquidityHookParams calldata params,
        IERC20[] memory erc4626PoolTokens,
        uint256[] memory amountsIn, //@audit amountsIn => actual amountsIn to give calculated by the addLiquidity call
        SwapKind kind,
        uint256[] memory limits //@audit limits => initial maxAmountIn for each token specified by caller (slippage)
    ) private returns (uint256[] memory underlyingAmounts, uint256[] memory wrappedAmounts) {
        uint256 poolTokensLength = erc4626PoolTokens.length;
        underlyingAmounts = new uint256[](poolTokensLength);
        wrappedAmounts = new uint256[](poolTokensLength);

        bool isStaticCall = EVMCallModeHelpers.isStaticCall();

        // Wrap given underlying tokens for wrapped tokens.
        for (uint256 i = 0; i < poolTokensLength; ++i) { //@audit loop through pool tokens
            // Treat all ERC4626 pool tokens as wrapped. The next step will verify if we can use the wrappedToken as
            // a valid ERC4626.
            IERC4626 wrappedToken = IERC4626(address(erc4626PoolTokens[i]));
            IERC20 underlyingToken = IERC20(_vault.getBufferAsset(wrappedToken));

            // If the Vault returns address 0 as underlying, it means that the ERC4626 token buffer was not
            // initialized. Thus, the Router treats it as a non-ERC4626 token.
            if (address(underlyingToken) == address(0)) { //@audit pool has non-ERC4626 token (i.e, USDC, WETH, DAI)
                underlyingAmounts[i] = amountsIn[i];
                wrappedAmounts[i] = amountsIn[i];

                if (isStaticCall == false) {
@>                  _takeTokenIn(params.sender, erc4626PoolTokens[i], amountsIn[i], params.wethIsEth); //@audit as we can see, the entire "amountIn" is taken from the user without any slippage check of "limit".
                }

                continue; //@audit skip the rest of the iteration if non-ERC4626
            }
            
            //@audit any token here is a valid ERC4626. Recall the "SwapKind" here is EXACT_OUT because we specified exact bpt we want out
            if (isStaticCall == false) {
                if (kind == SwapKind.EXACT_IN) {
                    // If the SwapKind is EXACT_IN, take the exact amount in from the sender.
                    _takeTokenIn(params.sender, underlyingToken, amountsIn[i], params.wethIsEth);
                } else {
                    // If the SwapKind is EXACT_OUT, the exact amount in is not known, because amountsIn is the
                    // amount of wrapped tokens. Therefore, take the limit. After the wrap operation, the difference
                    // between the limit and the actual underlying amount is returned to the sender.
                    _takeTokenIn(params.sender, underlyingToken, limits[i], params.wethIsEth); //@audit this is executed. Take the entire "maxAmountIn" limit from sender now, the unused amount is refunded at the end of the function
                }
            }

            // `erc4626BufferWrapOrUnwrap` will fail if the wrappedToken isn't ERC4626-conforming.
            (, underlyingAmounts[i], wrappedAmounts[i]) = _vault.erc4626BufferWrapOrUnwrap( //@audit Recall user owes wrapped token. This will find out how much equivalent unwrapped for that wrapped amount is to be paid for that user.
                BufferWrapOrUnwrapParams({
                    kind: kind, //@audit kind = EXACT_OUT
                    direction: WrappingDirection.WRAP,
                    wrappedToken: wrappedToken,
                    amountGivenRaw: amountsIn[i], //@audit amountOut of wrapped amount. This will be used to calculate how much amountIn underlying user must pay
                    limitRaw: limits[i] //@audit underlying amountIn slippage (correctly applies slippage)
                })
            );

            if (isStaticCall == false && kind == SwapKind.EXACT_OUT) {
                // If the SwapKind is EXACT_OUT, the limit of underlying tokens was taken from the user, so the
                // difference between limit and exact underlying amount needs to be returned to the sender.
                _vault.sendTo(underlyingToken, params.sender, limits[i] - underlyingAmounts[i]); //@audit Refund the unused amount underlying to the user
            }
        }
    }
```
Each pool token is looped through. If the pool token is a wrapped token (ERC4626), then it must have an underlying token. _vault.getBufferAsset(wrappedToken) will return the 0 address if the buffer is not registered (not a valid ERC4626 token):

VaultAdmin.sol#L663-L667
```javascript
function getBufferAsset( //@audit vault will delegatecall to vaultExtension which delegatecalls to vaultAdmin
        IERC4626 wrappedToken
    ) external view onlyVaultDelegateCall returns (address underlyingToken) {
        return _bufferAssets[wrappedToken];
    }
```
If it is not a valid ERC4626 token, then the token is directly taken from the sender via _takeTokenIn(params.sender, erc4626PoolTokens[i], amountsIn[i], params.wethIsEth);.

There lies the bug, we can see that amountsIn of that token is taken without checking the user's slippage (limits[i]).

I will not explain the rest of the function because it will overcomplicate the description of this finding. Just note that slippage is correctly incorporated if the token is indeed a valid ERC4626 wrapped token. So the zero-slippage token only applies to tokens that are not valid ERC4626 tokens (limits[] is not used at all).

The same applies when removing liquidity via CompositeLiquidityRouter::removeLiquidityProportionalFromERC4626Pool, but this time the slippage is minimum amount of liquidity out for burning exact amount of bpt.

CompositeLiquidityRouter.sol#L266-L275
```javascript
(, uint256[] memory wrappedAmountsOut, ) = _vault.removeLiquidity(
            RemoveLiquidityParams({
                pool: params.pool,
                from: params.sender,
                maxBptAmountIn: params.maxBptAmountIn,
@>              minAmountsOut: new uint256[](poolTokensLength), //@audit no slippage, empty list
                kind: params.kind,
                userData: params.userData
            })
        );
```
No slippage is checked for the actual removal of liquidity, which is fine as long as the minAmountsOut is checked.

CompositeLiquidityRouter.sol#L285-L291
```javascript
if (address(underlyingToken) == address(0)) {
                underlyingAmountsOut[i] = wrappedAmountsOut[i];
                if (isStaticCall == false) {
                    _sendTokenOut(params.sender, erc4626PoolTokens[i], underlyingAmountsOut[i], params.wethIsEth); //@audit minAmountsOut[i] not checked here
                }
                continue;
            }
```
But we can see that it is not checked, and the amount returned (which can be less than the minAmountOut specified) is given to the caller.

In the add liquidity case, the amount of tokens for each non-ERC4626 token spent by the user can exceed maxAmountIn, effectively draining their approval for those tokens.

In the remove liquidity case, the amount of tokens for each non-ERC4626 token sent to the user can be less than minAmountOut, effectively giving the user dust amount of token.

Consider the following example:

Let's say there exists a pool with the following tokens: ERC4626 token (lets call it waDAI) and WETH

Alice calls CompositeLiquidityRouter::addLiquidityProportionalToERC4626Pool. Attacker front-runs and deposits WETH (i.e, add singletoken liquidity, swap WETH, etc). When Alice's transaction is executed, to get the exact bpt out she specified, she must now pay much more WETH, which can drain the total amount she approved to the router. Her maxAmountIn slippage protection for the amount of WETH to give is ignored. Attacker back-runs and withdraws position, profiting on WETH, creating a successful sandwich attack scenario. Alice's approved WETH is drained (therefore this classifies as high, as mentioned in the competition page).

Note if the a pool contains more non-ERC4626 tokens, all of those tokens can be stolen from the caller.

## Recommendation

Apply the slippage protection specified by the user for non-ERC4626 tokens in addLiquidityProportionalToERC4626Pool and removeLiquidityProportionalFromERC4626Pool functions:
```diff
function _wrapTokens(
        AddLiquidityHookParams calldata params,
        IERC20[] memory erc4626PoolTokens,
        uint256[] memory amountsIn,
        SwapKind kind,
        uint256[] memory limits
    ) private returns (uint256[] memory underlyingAmounts, uint256[] memory wrappedAmounts) {
        uint256 poolTokensLength = erc4626PoolTokens.length;
        underlyingAmounts = new uint256[](poolTokensLength);
        wrappedAmounts = new uint256[](poolTokensLength);
        bool isStaticCall = EVMCallModeHelpers.isStaticCall();
        // Wrap given underlying tokens for wrapped tokens.
        for (uint256 i = 0; i < poolTokensLength; ++i) {
            // Treat all ERC4626 pool tokens as wrapped. The next step will verify if we can use the wrappedToken as
            // a valid ERC4626.
            IERC4626 wrappedToken = IERC4626(address(erc4626PoolTokens[i]));
            IERC20 underlyingToken = IERC20(_vault.getBufferAsset(wrappedToken));
            // If the Vault returns address 0 as underlying, it means that the ERC4626 token buffer was not
            // initialized. Thus, the Router treats it as a non-ERC4626 token.
            if (address(underlyingToken) == address(0)) {
                underlyingAmounts[i] = amountsIn[i];
                wrappedAmounts[i] = amountsIn[i];
                if (isStaticCall == false) {
+                    if(amountsIn[i] > limits[i] && limits[i] != 0) revert(); // must check limits[i] != 0 for `addLiquidityERC4626PoolUnbalancedHook` case
                    _takeTokenIn(params.sender, erc4626PoolTokens[i], amountsIn[i], params.wethIsEth);
                }
                continue;
            }
            if (isStaticCall == false) {
                if (kind == SwapKind.EXACT_IN) {
                    // If the SwapKind is EXACT_IN, take the exact amount in from the sender.
                    _takeTokenIn(params.sender, underlyingToken, amountsIn[i], params.wethIsEth);
                } else {
                    // If the SwapKind is EXACT_OUT, the exact amount in is not known, because amountsIn is the
                    // amount of wrapped tokens. Therefore, take the limit. After the wrap operation, the difference
                    // between the limit and the actual underlying amount is returned to the sender.
                    _takeTokenIn(params.sender, underlyingToken, limits[i], params.wethIsEth);
                }
            }
            // `erc4626BufferWrapOrUnwrap` will fail if the wrappedToken isn't ERC4626-conforming.
            (, underlyingAmounts[i], wrappedAmounts[i]) = _vault.erc4626BufferWrapOrUnwrap(
                BufferWrapOrUnwrapParams({
                    kind: kind,
                    direction: WrappingDirection.WRAP,
                    wrappedToken: wrappedToken,
                    amountGivenRaw: amountsIn[i],
                    limitRaw: limits[i]
                })
            );
            if (isStaticCall == false && kind == SwapKind.EXACT_OUT) {
                // If the SwapKind is EXACT_OUT, the limit of underlying tokens was taken from the user, so the
                // difference between limit and exact underlying amount needs to be returned to the sender.
                _vault.sendTo(underlyingToken, params.sender, limits[i] - underlyingAmounts[i]);
            }
        }
    }
function removeLiquidityERC4626PoolProportionalHook(
        RemoveLiquidityHookParams calldata params
    ) external nonReentrant onlyVault returns (uint256[] memory underlyingAmountsOut) {
        IERC20[] memory erc4626PoolTokens = _vault.getPoolTokens(params.pool);
        uint256 poolTokensLength = erc4626PoolTokens.length;
        underlyingAmountsOut = new uint256[](poolTokensLength);
        (, uint256[] memory wrappedAmountsOut, ) = _vault.removeLiquidity(
            RemoveLiquidityParams({
                pool: params.pool,
                from: params.sender,
                maxBptAmountIn: params.maxBptAmountIn,
                minAmountsOut: new uint256[](poolTokensLength),
                kind: params.kind,
                userData: params.userData
            })
        );
        bool isStaticCall = EVMCallModeHelpers.isStaticCall();
        for (uint256 i = 0; i < poolTokensLength; ++i) {
            IERC4626 wrappedToken = IERC4626(address(erc4626PoolTokens[i]));
            IERC20 underlyingToken = IERC20(_vault.getBufferAsset(wrappedToken));
            // If the Vault returns address 0 as underlying, it means that the ERC4626 token buffer was not
            // initialized. Thus, the Router treats it as a non-ERC4626 token.
            if (address(underlyingToken) == address(0)) {
                underlyingAmountsOut[i] = wrappedAmountsOut[i];
                if (isStaticCall == false) {
+                   if(underlyingAmountsOut[i] < params.minAmountsOut[i]) revert();
                    _sendTokenOut(params.sender, erc4626PoolTokens[i], underlyingAmountsOut[i], params.wethIsEth);
                }
                continue;
            }
            // `erc4626BufferWrapOrUnwrap` will fail if the wrappedToken is not ERC4626-conforming.
            (, , underlyingAmountsOut[i]) = _vault.erc4626BufferWrapOrUnwrap(
                BufferWrapOrUnwrapParams({
                    kind: SwapKind.EXACT_IN,
                    direction: WrappingDirection.UNWRAP,
                    wrappedToken: wrappedToken,
                    amountGivenRaw: wrappedAmountsOut[i],
                    limitRaw: params.minAmountsOut[i]
                })
            );
            if (isStaticCall == false) {
                _sendTokenOut(params.sender, underlyingToken, underlyingAmountsOut[i], params.wethIsEth);
            }
        }
    }
```

## [L-1] Executing buffer swap via BatchRouter by paying with ETH will always DoS

## Description

BatchRouter::swapExactIn and BatchRouter::swapExactOut allows users to faciliate multiple swaps within the Balancer Vault, for example DAI -> USDC -> WETH.

The pool specified in the arguments of each swap step will be the pool used for the respective swap. If the pool address provided is an ERC4626 vault (buffer), then a WRAP/UNWRAP is executed on the buffer within the Balancer vault.

For context, a buffer is not a pool, but it is quite similar. Within the Balancer vault, users can initialize buffers which consists of two tokens: the vault shares (wrapped token) and the vault asset (unwrapped token). You can learn more about ERC4626 vaults here: ERC4626 implementation.

Users can add/remove liquidity to the buffers as they please (add shares/underlying). Or, users can WRAP/UNWRAP:

Wrap: Convert underlying to shares. So the Vault receives underlying (i.e, DAI) from the caller, and gives ERC4626 shares in return (waDAI)

Unwrap: Opposite of WRAP, convert shares to underlying. So the vault shares (waDAI) and gives assets in return (DAI)

Learn more about buffers here: ERC4626 Liquidity Buffers

BatchRouter::swapExactIn and BatchRouter::swapExactOut also allows users to send ETH. Since there cannot be ETH pools within Vaults, the ETH is wrapped into WETH for the swap. This is useful if users or external protocols that have integrated the router are utilizing ETH (perhaps staking protocol, etc) and swap their ETH for another token. However, this is problematic for buffers, because the wrapping ETH to WETH option is always hardcoded to false, causing DoS.

## Proof of Concept

Let's observe the BatchRouter::swapExactIn, but note that this also applies to BatchRouter::swapExactOut.

BatchRouter.sol#L57-L84)
```javascript
function swapExactIn(
        SwapPathExactAmountIn[] memory paths,
        uint256 deadline,
@>      bool wethIsEth,
        bytes calldata userData
    )
        external
@>      payable
        saveSender
        returns (uint256[] memory pathAmountsOut, address[] memory tokensOut, uint256[] memory amountsOut)
    {
        return
            abi.decode(
                _vault.unlock(
                    abi.encodeCall(
                        BatchRouter.swapExactInHook,
                        SwapExactInHookParams({
                            sender: msg.sender,
                            paths: paths,
                            deadline: deadline,
                            wethIsEth: wethIsEth,
                            userData: userData
                        })
                    )
                ),
                (uint256[], address[], uint256[])
            );
    }
```
If wethIsEth == true, then ETH is wrapped to WETH for the swap. In other words, user is paying ETH to swap WETH->tokenA->tokenB->...->tokenOut. User only has to pay for the tokenIn, and they will receive tokenOut.

The vault::unlock callback will call swapExactInHook, where the following is executed:

BatchRouter.sol#L116-L150
```javascript
function swapExactInHook(
        SwapExactInHookParams calldata params
    )
        external
        nonReentrant
        onlyVault
        returns (uint256[] memory pathAmountsOut, address[] memory tokensOut, uint256[] memory amountsOut)
    {
@>      (pathAmountsOut, tokensOut, amountsOut) = _swapExactInHook(params); //@audit Compute amounts to pay user and for user to receive

        _settlePaths(params.sender, params.wethIsEth); //@audit This will take tokens from user and pay the user
    }

    function _swapExactInHook(
        SwapExactInHookParams calldata params
    ) internal returns (uint256[] memory pathAmountsOut, address[] memory tokensOut, uint256[] memory amountsOut) {
        // The deadline is timestamp-based: it should not be relied upon for sub-minute accuracy.
        // solhint-disable-next-line not-rely-on-time
        if (block.timestamp > params.deadline) {
            revert SwapDeadline();
        }

@>      pathAmountsOut = _computePathAmountsOut(params);

        // The hook writes current swap token and token amounts out.
        // We copy that information to memory to return it before it is deleted during settlement.
        tokensOut = _currentSwapTokensOut().values();
        amountsOut = new uint256[](tokensOut.length);
        for (uint256 i = 0; i < tokensOut.length; ++i) {
            amountsOut[i] =
                _currentSwapTokenOutAmounts().tGet(tokensOut[i]) +
                _settledTokenAmounts().tGet(tokensOut[i]);
            _settledTokenAmounts().tSet(tokensOut[i], 0);
        }
    }
```
_computePathAmountsOut handles the swaps, and compute how much the user has to pay of tokenIn and how much they receive of tokenOut. Then _settlePaths actually takes the tokens from the user and pays them.

However, there is a case where _computePathAmountsOut directly takes the token from the user, where they will not end up paying during the _settlePaths call:

BatchRouter.sol#L165-L168
```javascript
if (path.steps[0].isBuffer && EVMCallModeHelpers.isStaticCall() == false) {
        // If first step is a buffer, take the token in advance. We need this to wrap/unwrap.
         _takeTokenIn(params.sender, stepTokenIn, stepExactAmountIn, false); //@audit false hardcoded
    } else {
```
If the first step is a buffer, then take tokens directly from the user. Meaning, whatever tokens they are paying tokenIn, must be paid now. Notice that the last parameter is hardcoded to false.

RouterCommon.sol#L262
```javascript
function _takeTokenIn(address sender, IERC20 tokenIn, uint256 amountIn, bool wethIsEth) internal { //@audit wethIsEth is false
        // If the tokenIn is ETH, then wrap `amountIn` into WETH.
        if (wethIsEth && tokenIn == _weth) {
            if (address(this).balance < amountIn) {
                revert InsufficientEth();
            }

            // wrap amountIn to WETH.
            _weth.deposit{ value: amountIn }();
            // send WETH to Vault.
            _weth.safeTransfer(address(_vault), amountIn);
            // update Vault accounting.
            _vault.settle(_weth, amountIn);
        } else {
            if (amountIn > 0) {
                // Send the tokenIn amount to the Vault
                _permit2.transferFrom(sender, address(_vault), amountIn.toUint160(), address(tokenIn));
                _vault.settle(tokenIn, amountIn);
            }
        }
    }
```
We can see that if the user specified WETH, but paid with ETH, the call will revert because it will skip the wrapping to WETH and instead attempt to directly take WETH from the caller. This is not the case for any other swap, only when buffer is specified. If it is any other type of swap, then ETH will be wrapped to WETH correctly, as specified by caller.

Consider the following example:

A buffer exists with the following tokens: ERC4626 vault shares (we can call it waWETH), and it's corresponding underlying token: WETH.

Let's say there exists a weighted pool with two tokens: waWETH and USDC.

Alice wants to swap waWETH for USDC.

Alice calls swapExactIn with ETH value 100 ETH and specifies wethIsEth == true.

Her expectation is that the ETH will be wrapped into WETH, then the buffer will WRAP the WETH into waWETH, where a swap of waWETH for USDC will be executed.

However, due to the _takeTokenIn(params.sender, stepTokenIn, stepExactAmountIn, false) line, her call will revert causing DoS.

Note that a huge incentive for buffers is that it's wrapped asset (ERC4626 shares) can be used as a token within pools. Since WETH is a very popular token, this scenario is likely to occur.

Integrating protocols and users will suffer from DoS.

## Recommendation

If the user has paid with ETH and intends to have it wrapped with WETH, they will have set wethIsEth to true. Therefore, instead of hardcoding false, just pass in that parameter. This will correctly wrap the ETH to WETH as needed.

_computePathAmountsOut:
```diff
if (path.steps[0].isBuffer && EVMCallModeHelpers.isStaticCall() == false) {
        // If first step is a buffer, take the token in advance. We need this to wrap/unwrap.
-       _takeTokenIn(params.sender, stepTokenIn, stepExactAmountIn, false);
+       _takeTokenIn(params.sender, stepTokenIn, stepExactAmountIn, params.wethIsEth);
    } else {
```

_computePathAmountsIn: In this case, I believe it is still fine to take maxAmountIn, since any ETH that wasn't taken will be refunded during the _settlePaths call.
```diff
if (step.isBuffer) {
        if (stepLocals.isLastStep && EVMCallModeHelpers.isStaticCall() == false) {
            // The buffer will need this token to wrap/unwrap, so take it from the user in advance.
-           _takeTokenIn(params.sender, path.tokenIn, path.maxAmountIn, false);
+           _takeTokenIn(params.sender, path.tokenIn, amountIn, params.wethIsEth);
+           //_returnEth(params.sender); // No need for this line, since ETH will be refunded during `_settlePaths`, which is actually just after this function
```

## [L-2] CompositeLiquidityRouter does not handle case where buffer does not have sufficient wrapped/unwrapped amount

## Description

CompositeLiquidityRouter acts as the the entrypoint for add/remove liquidity operations on ERC4626 and nested pools. A nested pool is a pool that has at least one BPT token, which is essentially the LP token of another pool.

CompositeLiquidityRouter::addLiquidityUnbalancedNestedPoolHook allows users to faciliate add liquidity operation to these pools. It does this by specifying a "parent pool" and "child pool".

Let's say a pool has two tokens: DAI and BPT (Balance Pool Token => LP tokens of another pool). Now, this BPT token will be the same address as another pool. Let's say this pool has two tokens: WETH and USDC.

Therefore the parent pool in this case is the pool with DAI and BPT, and the child pool is the pool with WETH and USDC. Users can call addLiquidityUnbalancedNestedPoolHook to add liquidity to the parent pool by doing the following:

Specify amount of DAI, WETH, USDC to deposit
WETH and USDC will be deposited to the child pool, BPT (LP token) for that pool will be minted
The BPT that was just minted and the DAI will be used to add liquidity to the parent pool.
User successfully receives BPT for the parent pool.
One of the tokens within these pools can also be wrapped ERC4626 token. The Balancer vault consists of ERC4626 Liquidity Buffers, which has two tokens: vault shares (wrapped token) and the vault asset (unwrapped token).

So if a pool has wrapped ERC4626 token (i.e, waDAI), users can deposit the underlying (i.e, DAI) which will be wrapped and added to the pool.

When wrapping/unwrapping buffer tokens, it is possible that the buffer does not have enough wrapped/unwrapped tokens to handle the wrapping/unwrapping. The Balancer vault handles this case by directly executing an external call to the ERC4626 vault to WRAP/UNWRAP. To ensure a successful execution to the ERC4626 vault, the tokens the caller intends to WRAP or UNWRAP must be sent to the Balancer vault first. This way, it will have enough tokens to wrap/unwrap to the ERC4626 vault. This is handled all throughout the routers used in the Balancer protocol.

Example #1 where it's handled:

BatchRouter.sol#L165-L202
```javascript
if (path.steps[0].isBuffer && EVMCallModeHelpers.isStaticCall() == false) {
                // If first step is a buffer, take the token in advance. We need this to wrap/unwrap.
                _takeTokenIn(params.sender, stepTokenIn, stepExactAmountIn, false);
            }
            ...

                if (step.isBuffer) {
                    (, , uint256 amountOut) = _vault.erc4626BufferWrapOrUnwrap(
                        BufferWrapOrUnwrapParams({
                            kind: SwapKind.EXACT_IN,
                            direction: step.pool == address(stepTokenIn)
                                ? WrappingDirection.UNWRAP
                                : WrappingDirection.WRAP,
                            wrappedToken: IERC4626(step.pool),
                            amountGivenRaw: stepExactAmountIn,
                            limitRaw: minAmountOut
                        })
                    );
```
Example #2 where it's handled:

CompositeLiquidityRouter.sol#L310-L372
```javascript
function _wrapTokens(
        AddLiquidityHookParams calldata params,
        IERC20[] memory erc4626PoolTokens,
        uint256[] memory amountsIn,
        SwapKind kind,
        uint256[] memory limits
    ) private returns (uint256[] memory underlyingAmounts, uint256[] memory wrappedAmounts) {
        
       ...

            if (isStaticCall == false) { //@audit take underlying token before wrapping (_takeTokenIn operation sends it to the Balancer vault)
                if (kind == SwapKind.EXACT_IN) {
                    // If the SwapKind is EXACT_IN, take the exact amount in from the sender.
                    _takeTokenIn(params.sender, underlyingToken, amountsIn[i], params.wethIsEth);
                } else {
                    // If the SwapKind is EXACT_OUT, the exact amount in is not known, because amountsIn is the
                    // amount of wrapped tokens. Therefore, take the limit. After the wrap operation, the difference
                    // between the limit and the actual underlying amount is returned to the sender.
                    _takeTokenIn(params.sender, underlyingToken, limits[i], params.wethIsEth);
                }
            }

            // `erc4626BufferWrapOrUnwrap` will fail if the wrappedToken isn't ERC4626-conforming.
            (, underlyingAmounts[i], wrappedAmounts[i]) = _vault.erc4626BufferWrapOrUnwrap(
                BufferWrapOrUnwrapParams({
                    kind: kind,
                    direction: WrappingDirection.WRAP,
                    wrappedToken: wrappedToken,
                    amountGivenRaw: amountsIn[i],
                    limitRaw: limits[i]
                })
            );

            ...
    }
```
However, this case is not handled in CompositeLiquidityRouter during the addLiquidityUnbalancedNestedPoolHook, causing DoS.

## Proof of Concept

CompositeLiquidityRouter.sol#L379-L405
```javascript
function addLiquidityUnbalancedNestedPool(
        address parentPool,
@>      address[] memory tokensIn,
@>      uint256[] memory exactAmountsIn,
@>      uint256 minBptAmountOut,
        bytes memory userData
    ) external saveSender returns (uint256) {
        return
            abi.decode(
                _vault.unlock(
                    abi.encodeWithSelector(
                        CompositeLiquidityRouter.addLiquidityUnbalancedNestedPoolHook.selector,
                        AddLiquidityHookParams({
                            pool: parentPool,
                            sender: msg.sender,
                            maxAmountsIn: exactAmountsIn,
                            minBptAmountOut: minBptAmountOut,
                            kind: AddLiquidityKind.UNBALANCED,
                            wethIsEth: false,
                            userData: userData
                        }),
                        tokensIn
                    )
                ),
                (uint256)
            );
    }
```
Users specify the tokens to put in, exact amount of each token to put in, and the minimum bpt to receive. For context, an unbalanced add liquidity kind is when users add liquidity to a pool with exact amounts of any pool token, avoiding unnecessary dust in the user's wallet.

This will unlock the vault which will callback CompositeLiquidityRouter.addLiquidityUnbalancedNestedPoolHook:

CompositeLiquidityRouter.sol#L435-L518
```javascript
function addLiquidityUnbalancedNestedPoolHook(
        AddLiquidityHookParams calldata params,
        address[] memory tokensIn
    ) external nonReentrant onlyVault returns (uint256 exactBptAmountOut) {
        // Revert if tokensIn length does not match with maxAmountsIn length.
        InputHelpers.ensureInputLengthMatch(params.maxAmountsIn.length, tokensIn.length);

        bool isStaticCall = EVMCallModeHelpers.isStaticCall();

        // Loads a Set with all amounts to be inserted in the nested pools, so we don't need to iterate in the tokens
        // array to find the child pool amounts to insert.
        for (uint256 i = 0; i < tokensIn.length; ++i) { //@audit each token to add specified by the user is added to `_currentSwapTokenInAmounts` transient storage, paid at the end of this call
            _currentSwapTokenInAmounts().tSet(tokensIn[i], params.maxAmountsIn[i]);
        }

        IERC20[] memory parentPoolTokens = _vault.getPoolTokens(params.pool); //@audit returns pool tokens within parent pool

        // Iterate over each token of the parent pool. If it's a BPT, add liquidity unbalanced to it.
        for (uint256 i = 0; i < parentPoolTokens.length; i++) { //@audit loop through parent pool
            address childToken = address(parentPoolTokens[i]); //@audit get token address of parent pool

            if (_vault.isPoolRegistered(childToken)) { //@audit if the token is a BPT token (child pool), add liquidity to that pool, which will give BPT, used to add liquidity to the parent pool
                // Token is a BPT, so add liquidity to the child pool.

                IERC20[] memory childPoolTokens = _vault.getPoolTokens(childToken);
                uint256[] memory childPoolAmountsIn = _getPoolAmountsIn(childPoolTokens);

                // Add Liquidity will mint childTokens to the Vault, so the insertion of liquidity in the parent pool
                // will be a logic insertion, not a token transfer.
                (, uint256 exactChildBptAmountOut, ) = _vault.addLiquidity(
                    AddLiquidityParams({
                        pool: childToken,
                        to: address(_vault),
                        maxAmountsIn: childPoolAmountsIn,
                        minBptAmountOut: 0,
                        kind: params.kind,
                        userData: params.userData
                    })
                );

                // Sets the amount in of child BPT to the exactBptAmountOut of the child pool, so all the minted BPT
                // will be added to the parent pool.
                _currentSwapTokenInAmounts().tSet(childToken, exactChildBptAmountOut);

                // Since the BPT will be inserted into the parent pool, gets the credit from the inserted BPTs in
                // advance.
                _vault.settle(IERC20(childToken), exactChildBptAmountOut);
            } else if (
                _vault.isERC4626BufferInitialized(IERC4626(childToken)) && //@audit if pool contains wrapped token but user is paying with unwrapped
                _currentSwapTokenInAmounts().tGet(childToken) == 0 // wrapped amount in was not specified
            ) {
                // The ERC4626 token has a buffer initialized within the Vault. Additionally, since the sender did not
                // specify an input amount for the wrapped token, the function will wrap the underlying asset and use
                // the resulting wrapped tokens to add liquidity to the pool.
@>              _wrapAndUpdateTokenInAmounts(IERC4626(childToken));
            }
        }

        uint256[] memory parentPoolAmountsIn = _getPoolAmountsIn(parentPoolTokens);

        // Adds liquidity to the parent pool, mints parentPool's BPT to the sender and checks the minimum BPT out.
        (, exactBptAmountOut, ) = _vault.addLiquidity(
            AddLiquidityParams({
                pool: params.pool,
                to: isStaticCall ? address(this) : params.sender,
                maxAmountsIn: parentPoolAmountsIn,
                minBptAmountOut: params.minBptAmountOut,
                kind: params.kind,
                userData: params.userData
            })
        );

        // Since all values from _currentSwapTokenInAmounts are erased, recreates the set of amounts in so
        // `_settlePaths()` can charge the sender.
        for (uint256 i = 0; i < tokensIn.length; ++i) {
            _currentSwapTokensIn().add(tokensIn[i]);
            _currentSwapTokenInAmounts().tSet(tokensIn[i], params.maxAmountsIn[i]);
        }

        // Settle the amounts in.
        if (isStaticCall == false) {
@>          _settlePaths(params.sender, false); //@audit all tokens owed are paid here
        }
    }
```
If the pool contains wrapped tokens, but user is paying with unwrapped, then the token must be wrapped and sent to the vault.

CompositeLiquidityRouter.sol#L553-L578
```javascript
-   function _wrapAndUpdateTokenInAmounts(IERC4626 wrappedToken) private returns (uint256 wrappedAmountOut) {
        address underlyingToken = wrappedToken.asset();

        // Get the amountIn of underlying tokens informed by the sender.
        uint256 underlyingAmountIn = _currentSwapTokenInAmounts().tGet(underlyingToken);
        if (underlyingAmountIn == 0) {
            return 0;
        }

@>      (, , wrappedAmountOut) = _vault.erc4626BufferWrapOrUnwrap(
            BufferWrapOrUnwrapParams({
                kind: SwapKind.EXACT_IN,
                direction: WrappingDirection.WRAP,
                wrappedToken: wrappedToken,
                amountGivenRaw: underlyingAmountIn,
                limitRaw: uint256(0)
            })
        );

        // Remove the underlying amount from `_currentSwapTokenInAmounts` and add the wrapped amount.
        _currentSwapTokenInAmounts().tSet(underlyingToken, 0);
        _currentSwapTokenInAmounts().tSet(address(wrappedToken), wrappedAmountOut);

        // Updates the reserves of the vault with the wrappedToken amount.
        _vault.settle(IERC20(address(wrappedToken)), wrappedAmountOut);
    }
```
We can see that the unwrapped amount is not sent to the Balancer vault first, and a direct erc4626BufferWrapOrUnwrap call is made to the vault. If the buffer does not have enough liquidity to wrap/unwrap, then an external call to ERC4626 vault is made:

Vault.sol#L1211
```javascript
vaultWrappedDeltaHint = wrappedToken.deposit(vaultUnderlyingDeltaHint, address(this));
```
The only caveat is that the tokens to wrap must be sent to the Balancer vault first, otherwise it will not have sufficient funds to wrap during the external ERC4626 call. As mentioned, this is handled throughout all router functions except this one. This will cause the call to DoS and revert.

## Recommendation

Send the underlying amount to the Balancer vault first, then wrap it. Modify each instance of _wrapAndUpdateTokenInAmounts to pass in the sender.
```diff
-   function _wrapAndUpdateTokenInAmounts(IERC4626 wrappedToken) private returns (uint256 wrappedAmountOut) {
+   function _wrapAndUpdateTokenInAmounts(IERC4626 wrappedToken, address sender) private returns (uint256 wrappedAmountOut) {
        address underlyingToken = wrappedToken.asset();
        // Get the amountIn of underlying tokens informed by the sender.
        uint256 underlyingAmountIn = _currentSwapTokenInAmounts().tGet(underlyingToken);
        if (underlyingAmountIn == 0) {
            return 0;
        }
+       _takeTokenIn(sender, underlyingToken, underlyingAmountIn, false);
        (, , wrappedAmountOut) = _vault.erc4626BufferWrapOrUnwrap(
            BufferWrapOrUnwrapParams({
                kind: SwapKind.EXACT_IN,
                direction: WrappingDirection.WRAP,
                wrappedToken: wrappedToken,
                amountGivenRaw: underlyingAmountIn,
                limitRaw: uint256(0)
            })
        );
        // Remove the underlying amount from `_currentSwapTokenInAmounts` and add the wrapped amount.
        _currentSwapTokenInAmounts().tSet(underlyingToken, 0);
        _currentSwapTokenInAmounts().tSet(address(wrappedToken), wrappedAmountOut);
        // Updates the reserves of the vault with the wrappedToken amount.
        _vault.settle(IERC20(address(wrappedToken)), wrappedAmountOut);
    }
```
In addition, modifications must be made to ensure addLiquidityUnbalancedNestedPoolHook does not add the underlying owed to the _currentSwapTokenInAmounts again.

## [L-3] Vault lacks ability to enable query once disabled

## Description

The Balancer vault contains query functionality, giving anyone the ability to simulate a transaction without impacting the blockchain via eth_call. This is useful if a caller wants to decide how much slippage to incorporate in their transactions, what values to expect returned, etc.

Vault admin has the ability to disable this functionality:

VaultAdmin.sol#L407-L413
```javascript
function disableQuery() external onlyVaultDelegateCall authenticate {
        VaultStateBits vaultState = _vaultStateBits;
        vaultState = vaultState.setQueryDisabled(true);
        _vaultStateBits = vaultState;

        emit VaultQueriesDisabled();
    }
```
However, this will permanently disable any query functionality as there is no functionality to re-enable it again. Query calls/functions will permanently revert.

## Recommendation

Consider adding functionality for vault admin to re-enable queries.

## [L-4] Inadequate slippage protection for initializeBuffer, addLiquidityToBuffer, removeLiquidityFromBuffer functions

## Description

The Balancer vault consists of ERC4626 Liquidity Buffers, which has two tokens: vault shares (wrapped token) and the vault asset (unwrapped token).

Users can initialize a buffer where they must add liquidity during the initialization buffers, which must mint a minimum of 1e4 shares. The amount of shares minted is determined by a call to previewRedeem.

Users can proceed to add liquidity and remove liquidity from the buffer. The amount of liquidity taken/given to users is determined by the bufferBalances and totalShares.

These values can change prior to execution (i.e., while the call is in the mempool), causing a loss of funds for users.

The main flow users/external integrators will interact with the vault is through the router. However, the router doesn't incorporate slippage protection either for these functions, and doesn't even have the removeLiquidityFromBuffer functionality, so for that function users will have to directly interact with the vault.

Therefore, slippage should be enforced.

## Proof of Concept

VaultAdmin.sol#L443-L492
```javascript
function initializeBuffer(
        IERC4626 wrappedToken,
        uint256 amountUnderlyingRaw,
        uint256 amountWrappedRaw,
        address sharesOwner
    )
        public
        onlyVaultDelegateCall
        onlyWhenUnlocked
        whenVaultBuffersAreNotPaused
        nonReentrant
        returns (uint256 issuedShares)
    {
        if (_bufferAssets[wrappedToken] != address(0)) {
            revert BufferAlreadyInitialized(wrappedToken);
        }

        address underlyingToken = wrappedToken.asset();

        if (underlyingToken == address(0)) {
            // Should never happen, but a malicious wrapper could return the zero address and cause the buffer
            // initialization code to run more than once.
            revert InvalidUnderlyingToken(wrappedToken);
        }

        // Register asset of wrapper, so it cannot change.
        _bufferAssets[wrappedToken] = underlyingToken;

        // Take debt for initialization assets.
        _takeDebt(IERC20(underlyingToken), amountUnderlyingRaw);
        _takeDebt(wrappedToken, amountWrappedRaw);

        // Update buffer balances.
        _bufferTokenBalances[wrappedToken] = PackedTokenBalance.toPackedBalance(amountUnderlyingRaw, amountWrappedRaw);

        // At initialization, the initial "BPT rate" is 1, so the `issuedShares` is simply the sum of the initial
        // buffer token balances, converted to underlying. We use `previewRedeem` to convert wrapped to underlying,
        // since `redeem` is an EXACT_IN operation that rounds down the result.
@>      issuedShares = wrappedToken.previewRedeem(amountWrappedRaw) + amountUnderlyingRaw;
        _ensureBufferMinimumTotalSupply(issuedShares);

        // Divide `issuedShares` between the zero address, which receives the minimum supply, and the account
        // depositing the tokens to initialize the buffer, which receives the balance.
        issuedShares -= _BUFFER_MINIMUM_TOTAL_SUPPLY;

        _mintMinimumBufferSupplyReserve(wrappedToken);
        _mintBufferShares(wrappedToken, sharesOwner, issuedShares);

        emit LiquidityAddedToBuffer(wrappedToken, amountUnderlyingRaw, amountWrappedRaw);
    }
```
Amount of shares issued to the caller is determined by wrappedToken.previewRedeem(amountWrappedRaw) + amountUnderlyingRaw.

ERC4626.sol#L166-L168
```javascript
function previewRedeem(uint256 shares) public view virtual returns (uint256) {
        return _convertToAssets(shares, Math.Rounding.Floor);
    }
    ...
    function _convertToAssets(uint256 shares, Math.Rounding rounding) internal view virtual returns (uint256) {
        return shares.mulDiv(totalAssets() + 1, totalSupply() + 10 ** _decimalsOffset(), rounding);
    }
```
This is determined by the totalAssets and totalSupply, which can change prior to execution. => Alice can receive less shares than expected.

Similarly, for adding liquidity:

VaultAdmin.sol#L521-L526
```javascript
amountUnderlyingRaw = bufferBalances.getBalanceRaw().mulDivUp(exactSharesToIssue, totalShares);
        amountWrappedRaw = bufferBalances.getBalanceDerived().mulDivUp(exactSharesToIssue, totalShares);

        // Take debt for assets going into the buffer (wrapped and underlying).
        _takeDebt(IERC20(underlyingToken), amountUnderlyingRaw);
        _takeDebt(wrappedToken, amountWrappedRaw);
```
The caller specifies the exact shares to issue, but has no control over how much debt will be taken. This is determined by the current buffer balances and total shares, which can change prior to execution. Far more underlying and wrapped token can be drained, which is more likely if Alice is using the Router, since the Router is designed to take max approval (which is why anyone draining router approval is high severity for this contest).

Removing liquidity:

VaultAdmin.sol#L613-L622
```javascript
removedUnderlyingBalanceRaw = (bufferBalances.getBalanceRaw() * sharesToRemove) / totalShares;
        removedWrappedBalanceRaw = (bufferBalances.getBalanceDerived() * sharesToRemove) / totalShares;

        // We get the underlying token stored internally as opposed to calling `asset()` in the wrapped token.
        // This is to avoid any kind of unnecessary external call; the underlying token is set during initialization
        // and can't change afterwards, so it is already validated at this point. There is no way to add liquidity
        // with an asset that differs from the one set during initialization.
        IERC20 underlyingToken = IERC20(_bufferAssets[wrappedToken]);
        _supplyCredit(underlyingToken, removedUnderlyingBalanceRaw);
        _supplyCredit(wrappedToken, removedWrappedBalanceRaw);
```
Amount of underlying and wrapped token is again determined by buffer balances and total shares. In this case, far less underlying and wrapped amount can be credited.

You can also see here that the router doesn't incorporate any slippage protection either.

## Recommendation

Add slippage protection for these functions and ensure the router correctly handles the new changes.

Initialize buffer: Allow users to specify minimum amount of shares minted

Add liquidity: Allow users to specify maximum underlying and wrapped to take

Remove liquidity: Allow users to specify minimum amount of underlying and wrapped credited

## [L-5] Pools can DoS removeLiquidityRecovery, breaking protocol invariant

## Description

If a pool is paused, or the vault is paused (or both pool and vault), pools can enter recovery mode.

VaultAdmin.sol#L345-L355
```javascript
function enableRecoveryMode(address pool) external onlyVaultDelegateCall withRegisteredPool(pool) {
        _ensurePoolNotInRecoveryMode(pool);

        // If the Vault or pool is pausable (and currently paused), this call is permissionless.
        if (_isPoolPaused(pool) == false && _isVaultPaused() == false) {
            // If not permissionless, authenticate with governance.
            _authenticateCaller();
        }

        _setPoolRecoveryMode(pool, true);
    }
```
During this time, all regular swap/add liquidity/remove liquidty operations are unavailable, except for VaultExtension::removeLiquidityRecovery. This allows LPs to safely remove their position during this period, effectively creating a withdrawal during pause period.

VaultExtension.sol#L739-L807
```javascript
function removeLiquidityRecovery(
        address pool,
        address from,
        uint256 exactBptAmountIn
    )
        external
        onlyVaultDelegateCall
        onlyWhenUnlocked
        nonReentrant
        withInitializedPool(pool)
        onlyInRecoveryMode(pool)
        returns (uint256[] memory amountsOutRaw)
    {
        // Retrieve the mapping of tokens and their balances for the specified pool.
        mapping(uint256 tokenIndex => bytes32 packedTokenBalance) storage poolTokenBalances = _poolTokenBalances[pool];

        // Initialize arrays to store tokens and balances based on the number of tokens in the pool.
        IERC20[] memory tokens = _poolTokens[pool];
        uint256 numTokens = tokens.length;

        uint256[] memory balancesRaw = new uint256[](numTokens);
        bytes32 packedBalances;

        for (uint256 i = 0; i < numTokens; ++i) {
            balancesRaw[i] = poolTokenBalances[i].getBalanceRaw();
        }

        amountsOutRaw = BasePoolMath.computeProportionalAmountsOut(balancesRaw, _totalSupply(pool), exactBptAmountIn);

        for (uint256 i = 0; i < numTokens; ++i) {
            // Credit token[i] for amountOut.
            _supplyCredit(tokens[i], amountsOutRaw[i]);

            // Compute the new Pool balances. A Pool's token balance always decreases after an exit
            // (potentially by 0).
            balancesRaw[i] -= amountsOutRaw[i];
        }

        ...

@>      _burn(pool, from, exactBptAmountIn);

        ...
    }
```
Looking at the documentation for removeLiquidityRecovery:

IVaultAdmin.sol#L216-L223
```javascript
/**
     * @notice Enable recovery mode for a pool.
     * @dev This is a permissioned function. It enables a safe proportional withdrawal, with no external calls.
     * Since there are no external calls, live balances cannot be updated while in Recovery Mode.
     *
     * @param pool The address of the pool
     */
    function enableRecoveryMode(address pool) external;
```
IVaultExtension.sol#L407-L421
```javascript
/**
     * @notice Remove liquidity from a pool specifying exact pool tokens in, with proportional token amounts out.
     * The request is implemented by the Vault without any interaction with the pool, ensuring that
     * it works the same for all pools, and cannot be disabled by a new pool type.
     *
     * @param pool Address of the pool
     * @param from Address of user to burn pool tokens from
     * @param exactBptAmountIn Input pool token amount
     * @return amountsOut Actual calculated amounts of output tokens, sorted in token registration order
     */
    function removeLiquidityRecovery(
        address pool,
        address from,
        uint256 exactBptAmountIn
    ) external returns (uint256[] memory amountsOut);
```
"The request is implemented by the Vault without any interaction with the pool, ensuring that it works the same for all pools, and cannot be disabled by a new pool type."

As we can see, the vault intentionally does not interact with the pool and does not call any hooks during the removeLiquidityRecovery call. This is to ensure that no pool/hook can interfere with the recovery process of liquidity removal.

However, that is not entirely true.

Looking closer at the _burn(pool, from, exactBptAmountIn) call:

ERC20MultiToken.sol#L122-L145
```javascript
function _burn(address pool, address from, uint256 amount) internal {
        if (from == address(0)) {
            revert ERC20InvalidSender(from);
        }

        uint256 accountBalance = _balances[pool][from];
        if (amount > accountBalance) {
            revert ERC20InsufficientBalance(from, accountBalance, amount);
        }

        unchecked {
            _balances[pool][from] = accountBalance - amount;
        }
        uint256 newTotalSupply = _totalSupplyOf[pool] - amount;

        _ensurePoolMinimumTotalSupply(newTotalSupply);

        _totalSupplyOf[pool] = newTotalSupply;

        emit Transfer(pool, from, address(0), amount);

        // We also emit the "transfer" event on the pool token to ensure full compliance with the ERC20 standard.
@>      BalancerPoolToken(pool).emitTransfer(from, address(0), amount);
    }
```
We can see an external call is made directly to the emitTransfer function of the pool. If the pool reverts this call during recovery mode, it will permanently DoS removeLiquidityRecovery, breaking the invariant.

Submitting as medium severity since invariant is broken and falls under "A DoS that can prevent access to more than 5% of total TVL for more than 1 minute, for less money than the value of the funds in question."

In addition, user funds are locked despite recovery mode enabled.

## Recommendation

In the case of recovery mode, do not make an external call to the pool to emit the event. Instead, emit it directly from the same contract.

## [I-1] CompositeLiquidityRouter does not support wrapping if parent/child pools have wrapped token and its corresponding underlying

## Description

CompositeLiquidityRouter acts as the the entrypoint for add/remove liquidity operations on ERC4626 and nested pools. A nested pool is a pool that has at least one BPT token, which is essentially the LP token of another pool.

CompositeLiquidityRouter::addLiquidityUnbalancedNestedPoolHook allows users to faciliate add liquidity operation to these pools. It does this by specifying a "parent pool" and "child pool".

Let's say a pool has two tokens: DAI and BPT (Balance Pool Token => LP tokens of another pool). Now, this BPT token will be the same address as another pool. Let's say this pool has two tokens: WETH and USDC.

Therefore the parent pool in this case is the pool with DAI and BPT, and the child pool is the pool with WETH and USDC. Users can call addLiquidityUnbalancedNestedPoolHook to add liquidity to the parent pool by doing the following:

Specify amount of DAI, WETH, USDC to deposit
WETH and USDC will be deposited to the child pool, BPT (LP token) for that pool will be minted
The BPT that was just minted and the DAI will be used to add liquidity to the parent pool.
User successfully receives BPT for the parent pool.
One of the tokens within these pools can also be wrapped ERC4626 token. The Balancer vault consists of ERC4626 Liquidity Buffers, which has two tokens: vault shares (wrapped token) and the vault asset (unwrapped token).

So if a pool has wrapped ERC4626 token (i.e, waDAI), users can deposit the underlying (i.e, DAI) which will be wrapped and added to the pool.

The problem is, CompositeLiquidityRouter::addLiquidityUnbalancedNestedPoolHook does not work correctly in the following case:

Parent/child pool has a wrapped asset (i.e waDAI), and parent/child pool also has the underlying for that wrapped asset (i.e, DAI)

Let's say the parent pool has DAI, and the child pool has ERC4626 token waDAI (which has underlying DAI). The problem here is it that if the user specifies to pay with unwrapped, it will wrap the entire amount of underlying specified to pay for the waDAI in the childpool, but zero amount of DAI will be added to the parent pool. This can cause DoS due to insufficient bpt minted. This problem also occurs if the parent pool has a wrapped token and the it's unwrapped version (i.e, parent pool has waDAI and DAI).

## Proof of Concept

CompositeLiquidityRouter.sol#L379-L405
```javascript
function addLiquidityUnbalancedNestedPool(
        address parentPool,
@>      address[] memory tokensIn,
@>      uint256[] memory exactAmountsIn,
@>      uint256 minBptAmountOut,
        bytes memory userData
    ) external saveSender returns (uint256) {
        return
            abi.decode(
                _vault.unlock(
                    abi.encodeWithSelector(
                        CompositeLiquidityRouter.addLiquidityUnbalancedNestedPoolHook.selector,
                        AddLiquidityHookParams({
                            pool: parentPool,
                            sender: msg.sender,
                            maxAmountsIn: exactAmountsIn,
                            minBptAmountOut: minBptAmountOut,
                            kind: AddLiquidityKind.UNBALANCED,
                            wethIsEth: false,
                            userData: userData
                        }),
                        tokensIn
                    )
                ),
                (uint256)
            );
    }
```
Users specify the tokens to put in, exact amount of each token to put in, and the minimum bpt to receive. For context, an unbalanced add liquidity kind is when users add liquidity to a pool with exact amounts of any pool token, avoiding unnecessary dust in the user's wallet.

This will unlock the vault which will callback CompositeLiquidityRouter.addLiquidityUnbalancedNestedPoolHook:

CompositeLiquidityRouter.sol#L435-L518
```javascript
function addLiquidityUnbalancedNestedPoolHook(
        AddLiquidityHookParams calldata params,
        address[] memory tokensIn
    ) external nonReentrant onlyVault returns (uint256 exactBptAmountOut) {
        // Revert if tokensIn length does not match with maxAmountsIn length.
        InputHelpers.ensureInputLengthMatch(params.maxAmountsIn.length, tokensIn.length);

        bool isStaticCall = EVMCallModeHelpers.isStaticCall();

        // Loads a Set with all amounts to be inserted in the nested pools, so we don't need to iterate in the tokens
        // array to find the child pool amounts to insert.
        for (uint256 i = 0; i < tokensIn.length; ++i) { //@audit each token to add specified by the user is added to `_currentSwapTokenInAmounts` transient storage, paid at the end of this call
            _currentSwapTokenInAmounts().tSet(tokensIn[i], params.maxAmountsIn[i]);
        }

        IERC20[] memory parentPoolTokens = _vault.getPoolTokens(params.pool); //@audit returns pool tokens within parent pool

        // Iterate over each token of the parent pool. If it's a BPT, add liquidity unbalanced to it.
        for (uint256 i = 0; i < parentPoolTokens.length; i++) { //@audit loop through parent pool
            address childToken = address(parentPoolTokens[i]); //@audit get token address of parent pool

            if (_vault.isPoolRegistered(childToken)) { //@audit if the token is a BPT token (child pool), add liquidity to that pool, which will give BPT, used to add liquidity to the parent pool
                // Token is a BPT, so add liquidity to the child pool.

                IERC20[] memory childPoolTokens = _vault.getPoolTokens(childToken);
@>              uint256[] memory childPoolAmountsIn = _getPoolAmountsIn(childPoolTokens);

                // Add Liquidity will mint childTokens to the Vault, so the insertion of liquidity in the parent pool
                // will be a logic insertion, not a token transfer.
                (, uint256 exactChildBptAmountOut, ) = _vault.addLiquidity(
                    AddLiquidityParams({
                        pool: childToken,
                        to: address(_vault),
@>                      maxAmountsIn: childPoolAmountsIn,
                        minBptAmountOut: 0,
                        kind: params.kind,
                        userData: params.userData
                    })
                );

                // Sets the amount in of child BPT to the exactBptAmountOut of the child pool, so all the minted BPT
                // will be added to the parent pool.
                _currentSwapTokenInAmounts().tSet(childToken, exactChildBptAmountOut);

                // Since the BPT will be inserted into the parent pool, gets the credit from the inserted BPTs in
                // advance.
                _vault.settle(IERC20(childToken), exactChildBptAmountOut);
            } else if (
                _vault.isERC4626BufferInitialized(IERC4626(childToken)) &&
                _currentSwapTokenInAmounts().tGet(childToken) == 0 // wrapped amount in was not specified
            ) {
                // The ERC4626 token has a buffer initialized within the Vault. Additionally, since the sender did not
                // specify an input amount for the wrapped token, the function will wrap the underlying asset and use
                // the resulting wrapped tokens to add liquidity to the pool.
                _wrapAndUpdateTokenInAmounts(IERC4626(childToken));
            }
        }

@>      uint256[] memory parentPoolAmountsIn = _getPoolAmountsIn(parentPoolTokens);

        // Adds liquidity to the parent pool, mints parentPool's BPT to the sender and checks the minimum BPT out.
        (, exactBptAmountOut, ) = _vault.addLiquidity(
            AddLiquidityParams({
                pool: params.pool,
                to: isStaticCall ? address(this) : params.sender,
@>              maxAmountsIn: parentPoolAmountsIn,
                minBptAmountOut: params.minBptAmountOut,
                kind: params.kind,
                userData: params.userData
            })
        );

        // Since all values from _currentSwapTokenInAmounts are erased, recreates the set of amounts in so
        // `_settlePaths()` can charge the sender.
        for (uint256 i = 0; i < tokensIn.length; ++i) {
            _currentSwapTokensIn().add(tokensIn[i]);
            _currentSwapTokenInAmounts().tSet(tokensIn[i], params.maxAmountsIn[i]);
        }

        // Settle the amounts in.
        if (isStaticCall == false) {
            _settlePaths(params.sender, false);
        }
    }
```
If the parent pool contains a BPT token, that BPT token is the LP token of another pool, (address of BPT == address of pool). Therefore, this pool is the child pool, and the main pool is called the parent pool.

Liquidity is added to the child pool which will pay for the BPT tokens that the user owes in the add liquidity operation of the parent pool.

The amount of each token to add within the child pool is calculated by uint256[] memory childPoolAmountsIn = _getPoolAmountsIn(childPoolTokens);

CompositeLiquidityRouter.sol#L525-L547
```javascript
function _getPoolAmountsIn(IERC20[] memory poolTokens) private returns (uint256[] memory poolAmountsIn) {
        poolAmountsIn = new uint256[](poolTokens.length);

        for (uint256 j = 0; j < poolTokens.length; j++) {
            address poolToken = address(poolTokens[j]);
            if (
@>              _vault.isERC4626BufferInitialized(IERC4626(poolToken)) &&
                _currentSwapTokenInAmounts().tGet(poolToken) == 0 // wrapped amount in was not specified
            ) {
                // The token is an ERC4626 and has a buffer initialized within the Vault. Additionally, since the
                // sender did not specify an input amount for the wrapped token, the function will wrap the underlying
                // asset and use the resulting wrapped tokens to add liquidity to the pool.
@>              uint256 wrappedAmount = _wrapAndUpdateTokenInAmounts(IERC4626(poolToken));
                poolAmountsIn[j] = wrappedAmount;
            } else {
                poolAmountsIn[j] = _currentSwapTokenInAmounts().tGet(poolToken); //@audit get entire amount of `exact amountIn` specified by caller for the token
                // This operation does not support adding liquidity multiple times to the same token. So, we set
                // the amount in of the child pool token to 0. If the same token appears more times, the amount in
                // will be 0 for any other pool.
                _currentSwapTokenInAmounts().tSet(poolToken, 0); //@audit reset the amount to 0
            }
        }
    }
```
If the child pool contains wrapped amount ERC4626 token, we need to know the equivalent wrapped amount of the unwrapped amount the user is paying with. (i.e, user paying DAI, we need to know how much waDAI is equivalent).

CompositeLiquidityRouter.sol#L553-L578
```javascript
function _wrapAndUpdateTokenInAmounts(IERC4626 wrappedToken) private returns (uint256 wrappedAmountOut) {
        address underlyingToken = wrappedToken.asset();

        // Get the amountIn of underlying tokens informed by the sender.
@>      uint256 underlyingAmountIn = _currentSwapTokenInAmounts().tGet(underlyingToken); //@audit unwrapped amount user is paying with
        if (underlyingAmountIn == 0) {
            return 0;
        }

@>      (, , wrappedAmountOut) = _vault.erc4626BufferWrapOrUnwrap( //@audit get the equivalent wrapped amount
            BufferWrapOrUnwrapParams({
                kind: SwapKind.EXACT_IN,
                direction: WrappingDirection.WRAP,
                wrappedToken: wrappedToken,
@>              amountGivenRaw: underlyingAmountIn,
                limitRaw: uint256(0)
            })
        );

        // Remove the underlying amount from `_currentSwapTokenInAmounts` and add the wrapped amount.
        _currentSwapTokenInAmounts().tSet(underlyingToken, 0); //@audit set unwrapped amount to 0
        _currentSwapTokenInAmounts().tSet(address(wrappedToken), wrappedAmountOut);

        // Updates the reserves of the vault with the wrappedToken amount.
        _vault.settle(IERC20(address(wrappedToken)), wrappedAmountOut);
    }
```
This will wrap the entire amount of underlying, and set the tokenIn for the underlying to 0 via _currentSwapTokenInAmounts().tSet(underlyingToken, 0);.

So if that same token exists within the same child pool or the parent pool, 0 amount will be added. This can DoS due to insufficient BPT minted (less than bpt out specified by caller).

Consider the following examples:

Parent pool: DAI, BPT. Child pool: waDAI, WETH.
User intends to pay 50 DAI to parent pool, 50 DAI (which will be wrapped to waDAI) and 10 WETH to child pool. The entire 100 DAI will be wrapped to waDAI, leaving none for the parent pool.

Parent pool: wDAI, DAI
User itends to pay 100 DAI, of which 50 will be wrapped to waDAI. The entire 100 DAI will be wrapped to waDAI, thus only paying with waDAI and zero DAI.

Parent pool: WETH, BPT. Child pool: waDAI, DAI.
Similar to example 2, the entire amount of DAI specified is wrapped to waDAI. Therefore no amount of DAI can be added to child pool.

These cases will likely cause DoS due to insufficient BPT minted, since the liquidity added is only single sided.

## Recommendation

Perhaps document that wrapping is not supported if the wrapped token's corresponding unwrapped token is within the parent or child pool.


## [I-2] VaultFactory can be forced to revert

## Description

VaultFactory deploys the vault, which can only be deployed once

VaultFactory.sol#L72-L135
```javascript
function create(
@>      bytes32 salt,
        address targetAddress,
        bytes calldata vaultCreationCode,
        bytes calldata vaultAdminCreationCode,
        bytes calldata vaultExtensionCreationCode
    ) external authenticate {
        if (vaultCreationCodeHash != keccak256(vaultCreationCode)) {
            revert InvalidBytecode("Vault");
        } else if (vaultAdminCreationCodeHash != keccak256(vaultAdminCreationCode)) {
            revert InvalidBytecode("VaultAdmin");
        } else if (vaultExtensionCreationCodeHash != keccak256(vaultExtensionCreationCode)) {
            revert InvalidBytecode("VaultExtension");
        }

        address vaultAddress = getDeploymentAddress(salt);
        if (targetAddress != vaultAddress) {
            revert VaultAddressMismatch();
        }

        ProtocolFeeController feeController = new ProtocolFeeController(IVault(vaultAddress));

        VaultAdmin vaultAdmin = VaultAdmin(
            payable(
                Create2.deploy(
                    0,
@>                  bytes32(0x00), //@audit predictable salt
                    abi.encodePacked(
                        vaultAdminCreationCode,
                        abi.encode(
                            IVault(vaultAddress),
                            _pauseWindowDuration,
                            _bufferPeriodDuration,
                            _minTradeAmount,
                            _minWrapAmount
                        )
                    )
                )
            )
        );

        VaultExtension vaultExtension = VaultExtension(
            payable(
                Create2.deploy(
                    0,
@>                  bytes32(uint256(0x01)), //@audit predictable salt
                    abi.encodePacked(vaultExtensionCreationCode, abi.encode(vaultAddress, vaultAdmin))
                )
            )
        );

        address deployedAddress = CREATE3.deploy(
@>          salt, //@audit predictable salt
            abi.encodePacked(vaultCreationCode, abi.encode(vaultExtension, _authorizer, feeController)),
            0
        );

        // This should always be the case, but we enforce the end state to match the expected outcome anyway.
        if (deployedAddress != vaultAddress) {
            revert VaultAddressMismatch();
        }

        emit VaultCreated(vaultAddress);
    }
```
There are a total of three contracts deployed, VaultExtension, VaultAdmin, and the Vault, which all use predictable salts within the create2 calls.

VaultAdmin salt: bytes32(0x00), VaultExtension salt: 0, Vault salt is passed in the function parameter.

An attacker can front-run each call to create, extract the parameters, and invoke Create2 on any of the contracts intended to be deployed. This will cause VaultFactory::create to revert because the address is already deployed, causing create2 to fail (openzeppelin create2 library and solmate revert if create2 fails)

An attacker only needs to call Create2 on vault admin or vault extension. This means that the contract deployment for the actual vault will be unsuccessful because one of vault admin or vault extension is already deployed.

## Recommendation

Avoid using salts that can be used by a front-runner

## [I-3] removeLiquidityRecovery should have slippage protection

## Description

If a pool is paused, or the vault is paused (or both pool and vault), pools can enter recovery mode.

VaultAdmin.sol#L345-L355
```javascript
function enableRecoveryMode(address pool) external onlyVaultDelegateCall withRegisteredPool(pool) {
        _ensurePoolNotInRecoveryMode(pool);

        // If the Vault or pool is pausable (and currently paused), this call is permissionless.
        if (_isPoolPaused(pool) == false && _isVaultPaused() == false) {
            // If not permissionless, authenticate with governance.
            _authenticateCaller();
        }

        _setPoolRecoveryMode(pool, true);
    }
```
During this time, all regular swap/add liquidity/remove liquidty operations are unavailable, except for VaultExtension::removeLiquidityRecovery. This allows LPs to safely remove their position during this period, effectively creating a withdrawal during pause period.

VaultExtension.sol#L739-L807
```javascript
function removeLiquidityRecovery(
        address pool,
        address from,
        uint256 exactBptAmountIn
    )
        external
        onlyVaultDelegateCall
        onlyWhenUnlocked
        nonReentrant
        withInitializedPool(pool)
        onlyInRecoveryMode(pool)
        returns (uint256[] memory amountsOutRaw)
    {
        // Retrieve the mapping of tokens and their balances for the specified pool.
        mapping(uint256 tokenIndex => bytes32 packedTokenBalance) storage poolTokenBalances = _poolTokenBalances[pool];

        // Initialize arrays to store tokens and balances based on the number of tokens in the pool.
        IERC20[] memory tokens = _poolTokens[pool];
        uint256 numTokens = tokens.length;

        uint256[] memory balancesRaw = new uint256[](numTokens);
        bytes32 packedBalances;

        for (uint256 i = 0; i < numTokens; ++i) {
@>          balancesRaw[i] = poolTokenBalances[i].getBalanceRaw();
        }

@>      amountsOutRaw = BasePoolMath.computeProportionalAmountsOut(balancesRaw, _totalSupply(pool), exactBptAmountIn);

        for (uint256 i = 0; i < numTokens; ++i) {
            // Credit token[i] for amountOut.
@>          _supplyCredit(tokens[i], amountsOutRaw[i]);

            // Compute the new Pool balances. A Pool's token balance always decreases after an exit
            // (potentially by 0).
            balancesRaw[i] -= amountsOutRaw[i];
        }

        ...

        _burn(pool, from, exactBptAmountIn);

        ...
    }
```
We can see that the amount of underlying the user receives depends on balancesRaw (current balance of pool) and _totalSupply (current supply of BPT for the pool).

These values can change prior to function execution (i.e, while in the mempool), causing a loss of funds.

Consider the following example:

Alice attempts to burn 100 BPT for 1000 USDC. While her transaction is in the mempool, a large removal of liquidity is executed, decreasing the balances and totalSupply, causing Alice to receive 600 USDC instead. Alice suffers in this case and loses funds.

## Recommendation

Incorporate minimum amount out slippage protection for each token

## [I-4] Avalanche does not support transient storage

## Description

The sponsors have shared on discord the deployment chains on V2 as potential candidates for V3 deployment.

One of these chains included is Avalanche. However, Avalanche does not currently support transient storage operations.
```javascript
$ cast call --rpc-url https://rpc.ankr.com/avalanche --create 0x60005c
Error:
server returned an error response: error code -32000: invalid opcode: TLOAD
Therefore V3 is incompatible with this chain currently, and any execution will revert.
```

## Recommendation

Drop the transient storage model when deploying on this chain.

## [I-5] Router initialize pool may fail for 0 transfer tokens

## Description

Users can initialize pools through the router and specify "min amount" of tokens to add as liquidity.

Once their tokens are added, the router will attempt to transfer the amounts specified:

Router.sol#L104-L110
```javascript
} else {
                // Transfer tokens from the user to the Vault.
                // Any value over MAX_UINT128 would revert above in `initialize`, so this SafeCast shouldn't be
                // necessary. Done out of an abundance of caution.
                _permit2.transferFrom(params.sender, address(_vault), amountIn.toUint160(), address(token));
                _vault.settle(token, amountIn);
            }
```
However, the amount in can be 0 in case the user chooses not to add the specific token during initialization. If the token is a revert on 0 transfer token, this call will fail, causing initialization to fail.

## Recommendation

Check if amountIn > 0, like it's done in RouterCommon
