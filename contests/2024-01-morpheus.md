# Morpheus

[Morpheus AI](https://codehawks.cyfrin.io/c/2024-01-Morpheus) is a Smart Agent concept of connecting LLMs and AI Agents to wallets, Dapps, & smart contracts promises to open the world of Web3 to everyone. Chatting in normal language with your Smart Agent and having it understand the question or task, is similar to how Google's search engine opened the early internet up to the general public.

## Audit Findings Summary

| ID | Title | Severity |
|----|----------|----------|
| [L-1](#l-1-insufficient-gas-fee-estimation-for-cross-chain-message-delivery) | Insufficient Gas Fee Estimation for Cross-Chain Message Delivery | Medium |
---

## [L-1] Insufficient Gas Fee Estimation for Cross-Chain Message Delivery

## Summary
The `L1Sender` contract enables cross-chain communication by sending a message from Layer 1 to Layer 2 using the `LayerZero` protocol. However, the contract does not estimate the required gas fees for this operation, potentially resulting in users providing insufficient funds to cover gas fees. This can cause the transaction to fail, leading to a loss of tokens with an unsuccessful message delivery.

## Vulnerability Details
The contract allows users to specify an arbitrary amount of tokens to cover the gas fees for the cross-chain message delivery. However, without a prior estimation of the required fees (using LayerZero's `estimateFees()` function), users are at risk of underfunding the transaction. Enough gas is required to ensure the message delivery on the destination chain. If the provided msg.value is insufficient, the message fails to be delivered, but the tokens may still be deducted from the user's balance, effectively burning the user's tokens.

```javascript
    function sendMintMessage(address user_, uint256 amount_, address refundTo_) external payable onlyDistribution {
            RewardTokenConfig storage config = rewardTokenConfig;
​
            bytes memory receiverAndSenderAddresses_ = abi.encodePacked(config.receiver, address(this));
            bytes memory payload_ = abi.encode(user_, amount_);
​
            ILayerZeroEndpoint(config.gateway).send{value: msg.value}(
                config.receiverChainId, // communicator LayerZero chainId
                receiverAndSenderAddresses_, // send to this address to the communicator
                payload_, // bytes payload
                payable(refundTo_), // refund address
                address(0x0), // future parameter
                bytes("") // adapterParams (see "Advanced Features")
            );
        }
```

View the [layer zero docs](https://layerzero.gitbook.io/docs/evm-guides/contract-standards/estimating-message-fees) for more details.

## Impact
Users may experience direct financial loss due to token burn or loss in transactions intended for cross-chain operations. This issue undermines user trust in the contract's reliability for cross-chain functionality and poses a risk of token loss.

## Tools Used
Manual review.

## Recommendations
Integrate LayerZero's `estimateFees()` function to estimate the required gas fees for cross-chain message delivery. This can be used to inform users of the minimum msg.value needed or to automatically include the estimated fees in the transaction.
