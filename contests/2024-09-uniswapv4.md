# Uniswap V4

[The Uniswap protocol](https://cantina.xyz/code/e2cf6906-ec8b-4c78-a585-74ac90615659/overview) is a peer-to-peer system designed for exchanging cryptocurrencies (ERC-20 Tokens) on the Ethereum blockchain

## Audit Findings Summary

| ID | Title | Severity |
|----|----------|----------|
| [L-1](#l-1-positionmanager-lacks-a-receive-function-to-accept-native-token-causing-dos-in-some-cases) | PositionManager lacks a receive function to accept native token, causing DoS in some cases | Low |
| [L-2](#l-2-malicious-subscriber-contract-can-dos-positionmanagerburn-calls-in-positionmanagermodifyliquidity) | Malicious subscriber contract can DoS PositionManager::burn calls in PositionManager::modifyLiquidity | Low |
| [L-3](#l-3-malicious-subscriber-contract-can-dos-position-transfers) | Malicious subscriber contract can DoS position transfers | Low |
| [L-4](#l-4-v3swaprouter-is-vulnerable-to-a-birthday-attack) | V3SwapRouter is vulnerable to a birthday attack | Low |
---

## [L-1] PositionManager lacks a receive function to accept native token, causing DoS in some cases 

## Description

The PositionManager contract can be used by users to create new LP positions, where they will be minted an NFT corresponding to their position. Any changes to that position now must be done through PositionManager, such as increase/decrease liquidity, burn, etc.

Currently, this contract does not have a receive or fallback function, which means that sending native tokens directly to this contract would fail. This is problematic, because there are cases where this can cause DoS.

Consider the following scenarios:

Scenario #1:

Alice has multiple positions managed by PositionManager, and decides to utilize the Multicall feature to manage each position in one call. She decides to decrease ETH in one position and increase it another position, all in one transaction. Since msg.value is preserved through delegatecall, she specifies PositionManager as the receiver of the ETH via PoolManager::take(), but when the PoolManager contract attempts to send ETH to PositionManager, the call will revert, causing DoS.

Scenario #2:

Let's say there's a pool with a hook which incentivizes users to provide liquidity by paying for their gas fees upon creating a new LP position. It does this by sending native token to the caller specified when the afterAddLiquidity hook is executed, which will be the address of PositionManager. If a user decides to mint this position through PositionManager, the call will revert when the hook address attempts to send native token, causing DoS.

Scenario #3:

Alice has a position managed by PositionManager which is subscribed to an address that will reward msg.sender native token, which Alice intends to sweep from PositionManager. However, since there is no receive function, the call will revert, causing DoS.

There can be many cases where the PositionManager is on the receiving end of native token transfers, however each attempt will revert.

## Impact

Denial of Service in some cases when utilizing PositionManager

## Recommendation

Implement a receive function in PositionManager.

## [L-2] Malicious subscriber contract can DoS PositionManager::burn calls in PositionManager::modifyLiquidity

## Description

The PositionManager contract can be used by users to create new LP positions, where they will be minted an NFT corresponding to their position. Any changes to that position now must be done through PositionManager, such as increase/decrease liquidity, burn, etc.

Users can also add a subscriber receive notifications for their respective position, which can be used to integrate with external staking protocols/mechanisms.

Let's look at what happens when a user burns their position:

PositionManager.sol#L306-L328
```javascript
function _burn(uint256 tokenId, uint128 amount0Min, uint128 amount1Min, bytes calldata hookData)
        internal
        onlyIfApproved(msgSender(), tokenId)
    {
        (PoolKey memory poolKey, PositionInfo info) = getPoolAndPositionInfo(tokenId);

        uint256 liquidity = uint256(_getLiquidity(tokenId, poolKey, info.tickLower(), info.tickUpper()));

        // Clear the position info.
        positionInfo[tokenId] = PositionInfoLibrary.EMPTY_POSITION_INFO;
        // Burn the token.
        _burn(tokenId);

        // Can only call modify if there is non zero liquidity.
        if (liquidity > 0) {
            (BalanceDelta liquidityDelta, BalanceDelta feesAccrued) =
@>              _modifyLiquidity(info, poolKey, -(liquidity.toInt256()), bytes32(tokenId), hookData);
            // Slippage checks should be done on the principal liquidityDelta which is the liquidityDelta - feesAccrued
            (liquidityDelta - feesAccrued).validateMinOut(amount0Min, amount1Min);
        }

@>      if (info.hasSubscriber()) _unsubscribe(tokenId);
    }
```
We can see that the tokenId is unsubscribed from the subscriber contract at the end of the call. However, prior to that, _modifyLiquidity is called:

PositionManager.sol#L376-L397
```javascript
function _modifyLiquidity(
        PositionInfo info,
        PoolKey memory poolKey,
        int256 liquidityChange,
        bytes32 salt,
        bytes calldata hookData
    ) internal returns (BalanceDelta liquidityDelta, BalanceDelta feesAccrued) {
        (liquidityDelta, feesAccrued) = poolManager.modifyLiquidity(
            poolKey,
            IPoolManager.ModifyLiquidityParams({
                tickLower: info.tickLower(),
                tickUpper: info.tickUpper(),
                liquidityDelta: liquidityChange,
                salt: salt
            }),
            hookData
        );

        if (info.hasSubscriber()) {
@>          _notifyModifyLiquidity(uint256(salt), liquidityChange, feesAccrued);
        }
    }
```
This will notify the subscriber contract that the liquidity has been modified. A malicious subscriber can check if the LP intends to burn the position and subscribe by verifying the liquidityChange. To prevent them from burning and unsubscribing, they can revert the transaction through methods such as intentionally consume enough gas to cause DoS:

Notifier.sol#L82-L93
```javascript
function _notifyModifyLiquidity(uint256 tokenId, int256 liquidityChange, BalanceDelta feesAccrued) internal {
        ISubscriber _subscriber = subscriber[tokenId];

        bool success = _call(
            address(_subscriber),
            abi.encodeCall(ISubscriber.notifyModifyLiquidity, (tokenId, liquidityChange, feesAccrued))
        );

        if (!success) {
            Wrap__ModifyLiquidityNotificationReverted.selector.bubbleUpAndRevertWith(address(_subscriber));
        }
    }
```

## Impact

Denial of Service in some cases when utilizing PositionManager

## Recommendation

Implement a receive function in PositionManager.

## [L-3] Malicious subscriber contract can DoS position transfers

## Description

The PositionManager contract can be used by users to create new LP positions, where they will be minted an NFT corresponding to their position. Any changes to that position now must be done through PositionManager, such as increase/decrease liquidity, burn, etc.

Users can also add a subscriber receive notifications for their respective position, which can be used to integrate with external staking protocols/mechanisms.

The subscriber is notified upon subscribing, unsubscribing, modify liquidity, and tokenId transfers:

PositionManager.sol#L419-L423
```javascript
/// @dev overrides solmate transferFrom in case a notification to subscribers is needed
    function transferFrom(address from, address to, uint256 id) public virtual override {
        super.transferFrom(from, to, id);
        if (positionInfo[id].hasSubscriber()) _notifyTransfer(id, from, to);
    }
```
Which calls the internal _notifyTransfer to notify the subscriber:

Notifier.sol#L95-L104
```javascript
function _notifyTransfer(uint256 tokenId, address previousOwner, address newOwner) internal {
        ISubscriber _subscriber = subscriber[tokenId];

        bool success =
            _call(address(_subscriber), abi.encodeCall(ISubscriber.notifyTransfer, (tokenId, previousOwner, newOwner)));

        if (!success) {
            Wrap__TransferNotificationReverted.selector.bubbleUpAndRevertWith(address(_subscriber));
        }
    }
```
We can see here a malicious subscriber contract can DoS this call by reverting or consuming enough gas to cause the transaction to fail.

## Impact

DoS of transfers, user will have to manually unsubscribe and proceed to transfer

## Recommendation

Consider forwarding a specific amount of gas to ISubscriber.notifyTransfer, wrapped in a try/catch block.

## [L-4] V3SwapRouter is vulnerable to a birthday attack

## Description

V3SwapRouter::computePoolAddress is susceptible to a birthday attack

V3SwapRouter.sol#L155-L170
```javascript
function computePoolAddress(address tokenA, address tokenB, uint24 fee) private view returns (address pool) {
        if (tokenA > tokenB) (tokenA, tokenB) = (tokenB, tokenA);
        pool = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            hex'ff',
                            UNISWAP_V3_FACTORY,
                            keccak256(abi.encode(tokenA, tokenB, fee)),
                            UNISWAP_V3_POOL_INIT_CODE_HASH
                        )
                    )
                )
            )
        );
    }
```
The output of this function is a 160 bit EVM address, which takes approximately 2^80 tries to find a collision with an attacker controlled address via create2.

An attacker create a pool address completely controlled by them, allowing them to directly steal funds.

Similar findings:

Code4rena: https://github.com/code-423n4/2023-11-panoptic-findings/issues/128

Mysten Labs claim that, "a 2^80 attack would cost a few million dollars”: https://mystenlabs.com/blog/ambush-attacks-on-160bit-objectids-addresses

## Impact

It was discussed at length in the recent MakerDAO competition that this attack is far from feasible and has an extremely low likelyhood of occuring.

However, due to the funds at risk, which can be worth billions in TVL, I believe this issue warrants a low severity risk.

## Recommendation

Verify that the pool address returned via computePoolAddress is a valid pool
