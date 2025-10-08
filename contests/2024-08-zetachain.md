# ZetaChain

[ZetaChain](https://cantina.xyz/code/80a33cf0-ad69-4163-a269-d27756aacb5e/overview) is a L1 EVM compatible blockchain focused on connecting blockchains

## Audit Findings Summary

| ID | Title | Severity |
|----|----------|----------|
| [H-1](#h-1-gatewayzevm-is-missing-a-deposit-function-that-executes-_transferzeta-to-the-target-address-causing-loss-of-funds) | GatewayZEVM is missing a deposit function that executes _transferZETA to the target address, causing loss of funds | High |
| [M-1](#m-1-gatewayzevm-is-missing-a-deposit-function-that-executes-_transferzeta-to-the-target-address-causing-loss-of-funds) | GatewayZEVM is missing a deposit function that executes _transferZETA to the target address, causing loss of funds | Medium |
| [M-2](#m-2-zrc20gasprice-is-redundant-for-some-functions-as-users-are-incentivized-to-specify-gas-limit-0) | ZRC20::gasPrice is redundant for some functions, as users are incentivized to specify gas limit = 0 | Medium |
| [M-3](#m-3-malicious-user-can-call-gatewayevmdepositandcall-with-dust-amount-to-waste-gas-for-the-fungible-account) | Malicious user can call GatewayEVM::depositAndCall with dust amount to waste gas for the Fungible account | Medium |
| [M-4](#m-4-gatewayzevm-is-missing-functionality-to-refund-gaszrc20-tokens-for-reverted-transactions) | GatewayZEVM is missing functionality to refund gasZRC20 tokens for reverted transactions | Medium |
| [M-5](#m-5-users-can-lose-funds-if-calling-gatewayzevmcall-or-gatewayzevmwithdrawandcall-to-solana) | Users can lose funds if calling GatewayZEVM::call or GatewayZEVM::withdrawAndCall to Solana | Medium |
| [M-6](#m-6-tss_role-cannot-be-changed-by-admin-in-erc20custody-and-connector-contracts) | TSS_ROLE cannot be changed by admin in ERC20Custody and Connector contracts | Medium |
---

## [H-1] GatewayZEVM is missing a deposit function that executes _transferZETA to the target address, causing loss of funds

## Summary

If a user calls GatewayEVM::deposit on a connected chain by depositing zetaToken, they will not receive ZETA token on the ZetaChain.

This is because GatewayZEVM::deposit only handles transferring of ERC20 tokens, which mints the user ZRC20 tokens, and lacks any functionality to transfer the user ZETA token.

GatewayZEVM::depositAndCall is the only function capable of transferring ZETA token, but the problem is that the target address must be a contract compliant to the UniversalContract interface. If the target address is not a contract, which it may very well not be if someone is calling GatewayEVM::deposit, then the call will revert.

This will cause a loss of funds for the user who initially deposited zetaToken, since there is no functionality for them to receive ZETA token on the destination chain.

## Details

A user can call GatewayEVM::deposit or GatewayEVM::depositAndCall to initiate an inbound transaction from a connected chain, which will trigger an outbound transaction on the ZetaChain.

To complete the outbound transaction, the fungible account calls GatewayZEVM::deposit or GatewayZEVM::depositAndCall, depending on which function initiated the inbound event.

The only difference between them is that depositAndCall transfers the token to the target contract which must be compliant to the UniversalContract interface, whereas deposit will transfer the token to the target address which can be an EOA.

If the user deposited ERC20 tokens via GatewayEVM::depositAndCall, then the fungible account will call the GatewayZEVM::depositAndCall function which will mint them ZRC20 tokens on the ZetaChain:

GatewayZEVM.sol#L310-L327
```javascript
function depositAndCall(
        zContext calldata context,
        address zrc20,
        uint256 amount,
        address target,
        bytes calldata message
    )
        external
        onlyFungible
        whenNotPaused
    {
        if (zrc20 == address(0) || target == address(0)) revert ZeroAddress();
        if (amount == 0) revert InsufficientZRC20Amount();
        if (target == FUNGIBLE_MODULE_ADDRESS || target == address(this)) revert InvalidTarget();

@>      if (!IZRC20(zrc20).deposit(target, amount)) revert ZRC20DepositFailed();
        UniversalContract(target).onCrossChainCall(context, zrc20, amount, message);
    }
```
On the other hand, if the user deposited zetaToken via GatewayEVM::depositAndCall, then the fungible account will call the GatewayZEVM::depositAndCall function which will transfer ZETA tokens to them on the ZetaChain:

GatewayZEVM.sol#L334-L350
```javascript
function depositAndCall(
        zContext calldata context,
        uint256 amount,
        address target,
        bytes calldata message
    )
        external
        onlyFungible
        whenNotPaused
    {
        if (target == address(0)) revert ZeroAddress();
        if (amount == 0) revert InsufficientZetaAmount();
        if (target == FUNGIBLE_MODULE_ADDRESS || target == address(this)) revert InvalidTarget();

@>      _transferZETA(amount, target);
        UniversalContract(target).onCrossChainCall(context, zetaToken, amount, message);
    }
```
This works fine for depositAndCall, but the problem is that GatewayZEVM::deposit only has one of these options: it only mints ZRC20 tokens and does not have functionality to transfer ZETA.

So when a user calls GatewayEVM::deposit to deposit zetaToken, they cannot receive ZETA tokens via a GatewayZEVM::deposit call, since the following is the only deposit function in GatewayZEVM:

GatewayZEVM.sol#L273-L280
```javascript
function deposit(address zrc20, uint256 amount, address target) external onlyFungible whenNotPaused {
        if (zrc20 == address(0) || target == address(0)) revert ZeroAddress();
        if (amount == 0) revert InsufficientZRC20Amount();

        if (target == FUNGIBLE_MODULE_ADDRESS || target == address(this)) revert InvalidTarget();

@>      if (!IZRC20(zrc20).deposit(target, amount)) revert ZRC20DepositFailed(); //@audit this will mint the user zrc20 token, but no functionality to transfer them ZETA
    }
```
It only mints ZRC20 tokens but does not have any functionality for transferring ZETA tokens to the target.

In addition, attempting to call depositAndCall on the target address with the intention of transferring them ZETA will not work as a solution to this problem. This is because the target address for the initial GatewayEVM::deposit call does not have to be a contract, which means the UniversalContract(target).onCrossChainCall(context, zetaToken, amount, message) call will revert.

There is no other functionality to transfer the target address ZETA tokens, causing a loss of funds for the original depositer.

## Impact

Loss of funds for users who deposit zetaToken, especially since this zetaToken will be burned by the connector on EVM chains other than Ethereum. Since there is no functionality to transfer them ZETA, they may lose their zetaTokens. Also funds lost due to gas spent.

## Recommendation

Include another deposit function within GatewayZEVM that transfers ZETA tokens to the target address:
```diff
+   function deposit(
+       uint256 amount,
+       address target
+   )
+       external
+       onlyFungible
+       whenNotPaused
+   {
+       if (target == address(0)) revert ZeroAddress();
+       if (amount == 0) revert InsufficientZetaAmount();
+       if (target == FUNGIBLE_MODULE_ADDRESS || target == address(this)) revert InvalidTarget();
+
+       _transferZETA(amount, target);
+   }
```

## [M-1] GatewayZEVM is missing a deposit function that executes _transferZETA to the target address, causing loss of funds

## Summary

The following is the flow of cross chain interaction: inbound tx -> emit inbound event -> observer set generates outbound tx -> emit outbound event -> cctx finalized.

There are cases where once the inbound transaction is confirmed, the outbound transaction can revert. Unless the protocol refunds the user in this case, all funds will be lost.

Competition docs explain the flow of revert management, and sponsors on discord have confirmed that the refund/revert flow happens on the source chain.

For example, if a user decides to withdraw their ZETA tokens on the ZetaChain, they must send their ZETA to the Fungible account via a call to GatewayZEVM::withdraw, and should receive zetaToken on the destination chain by the TSS address. In case the call by the TSS address fails, the Fungible account will send back the ZETA to the user.

The problem is that the GatewayZEVM contract lacks functionality for this, causing a loss of funds for users.

## Details

Let's first discuss what happens when a user withdraws ZRC20 tokens. A call to GatewayZEVM::withdraw or GatewayZEVM::withdrawAndCall will be made, where the ZRC20 tokens are burned on ZetaChain, and the TSS address will proceed to transfer ERC20 tokens to the user on the destination chain. If this transaction reverts, then the Fungible account will proceed to mint the user new ZRC20 tokens, depending on which function the user originally called.

If the user's call to GatewayZEVM::withdraw failed, then the fungible account will proceed to call GatewayZEVM::deposit to refund (via minting) the amount of ZRC20 that was burned by the user.
If the user's call to GatewayZEVM::withdrawAndCall failed, then the fungible account will proceed to call GatewayZEVM::depositAndRevert.
GatewayZEVM.sol#L366-L382
```javascript
/// @notice Deposit foreign coins into ZRC20 and revert a user-specified contract on ZEVM.
    /// @param zrc20 The address of the ZRC20 token.
    /// @param amount The amount of tokens to revert.
    /// @param target The target contract to call.
    /// @param revertContext Revert context to pass to onRevert.
    function depositAndRevert(
        address zrc20,
        uint256 amount,
        address target,
        RevertContext calldata revertContext
    )
        external
        onlyFungible
        whenNotPaused
    {
        if (zrc20 == address(0) || target == address(0)) revert ZeroAddress();
        if (amount == 0) revert InsufficientZRC20Amount();
        if (target == FUNGIBLE_MODULE_ADDRESS || target == address(this)) revert InvalidTarget();

        if (!IZRC20(zrc20).deposit(target, amount)) revert ZRC20DepositFailed();
        UniversalContract(target).onRevert(revertContext);
    }
```
The problem is there is no deposit and depositAndRevert functionality that can transfer back the user ZETA if they intiiated a ZETA withdrawal:

GatewayZEVM.sol#L200-L215
```javascript
function withdraw(
        bytes memory receiver,
        uint256 amount,
        uint256 chainId,
        RevertOptions calldata revertOptions
    )
        external
        nonReentrant
        whenNotPaused
    {
        if (receiver.length == 0) revert ZeroAddress();
        if (amount == 0) revert InsufficientZetaAmount();

@>      _transferZETA(amount, FUNGIBLE_MODULE_ADDRESS);
        emit Withdrawn(msg.sender, chainId, receiver, address(zetaToken), amount, 0, 0, "", 0, revertOptions);
    }
```

GatewayZEVM.sol#L223-L239
```javascript
function withdrawAndCall(
        bytes memory receiver,
        uint256 amount,
        uint256 chainId,
        bytes calldata message,
        RevertOptions calldata revertOptions
    )
        external
        nonReentrant
        whenNotPaused
    {
        if (receiver.length == 0) revert ZeroAddress();
        if (amount == 0) revert InsufficientZetaAmount();

@>      _transferZETA(amount, FUNGIBLE_MODULE_ADDRESS);
        emit Withdrawn(msg.sender, chainId, receiver, address(zetaToken), amount, 0, 0, message, 0, revertOptions);
    }
```

ZETA tokens are transferred to the Fungible account and the Withdrawn inbound event is emitted. If the TSS address's function calls on the outbound event reverts, the Fungible account must refund the caller the ZETA tokens, just as how it's done with ZRC20 tokens. But there is no functionality for this within GatewayZEVM, causing loss of funds.

Note that the following function is not a solution to this problem

GatewayZEVM.sol#L334
```javascript
function depositAndCall(
        zContext calldata context,
        uint256 amount,
        address target,
        bytes calldata message
    )
        external
        onlyFungible
        whenNotPaused
    {
        if (target == address(0)) revert ZeroAddress();
        if (amount == 0) revert InsufficientZetaAmount();
        if (target == FUNGIBLE_MODULE_ADDRESS || target == address(this)) revert InvalidTarget();

        _transferZETA(amount, target);
        UniversalContract(target).onCrossChainCall(context, zetaToken, amount, message);
    }
```
This is because the target address must be a contract implementing onCrossChainCall, but that won't always be the case, EOA's may very well be the target address for the refund, causing this function to revert.

In additon, the onRevert call is not called in this function either, not allowing developers to decide "on how to they want to manage the revert" or "Example: a smart contract might want to define custom logic to react to a revert (unlocking some tokens, etc.. )" as intended with the design of reverts.

## Impact

Loss of funds for users, no functionality in GatewayZEVM for Fungible account to refund users on the ZetaChain with ZETA.

## Recommendation

Add deposit and depositAndRevert functionality to refund users ZETA:
```diff
+   function deposit(uint256 amount, address target) external onlyFungible whenNotPaused {
+       if (target == address(0)) revert ZeroAddress();
+       if (amount == 0) revert InsufficientZRC20Amount();
+       if (target == FUNGIBLE_MODULE_ADDRESS || target == address(this)) revert InvalidTarget();
+       _transferZETA(amount, target);
    }
+   function depositAndRevert(
+       uint256 amount,
+       address target,
+       RevertContext calldata revertContext
+   )
+       external
+       onlyFungible
+       whenNotPaused
+   {
+       if (target == address(0)) revert ZeroAddress();
+       if (amount == 0) revert InsufficientZRC20Amount();
+       if (target == FUNGIBLE_MODULE_ADDRESS || target == address(this)) revert InvalidTarget();
+       _transferZETA(amount, target);
+       UniversalContract(target).onRevert(revertContext);
    }
```

## [M-2] ZRC20::gasPrice is redundant for some functions, as users are incentivized to specify gas limit = 0

## Summary

GatewayZEVM::withdrawAndCall and GatewayZEVM::call allow the caller to specify the gas limit, which is used to determine the gas fees they must pay.

The problem is that there is no minimum gas limit check, therefore users are incentivized to pass in 0 amount for the gas limit, allowing them to avoid the gas price, causing a loss of funds for the protocol.

This differs from GatewayZEVM::withdraw, which utilizes the gas limit defined in the ZRC20 token contract.

## Details

The competition docs state the following as a successful outbound:

inbound tx -> emit inbound event -> observer set generates outbound tx -> emit outbound event -> cctx finalized.

Users have the ability to initiate an inbound event via the GatewayZEVM contract in 3 different ways:

GatewayZEVM::withdraw, which burns their tokens and emits a Withdrawn event that initiates an outbound event that mints/transfer the user tokens on the receiver.
GatewayZEVM::call, which emits a Called event that initiates an outbound event that calls a smart contract on an external chain.
GatewayZEVM::withdrawAndCall, which does both of the above.
The last two cases allow users to pass in a gasLimit, which determines the gasFee they pay for the inbound transaction. It's possible that the protocol's intention is that the more they specify to pay for the gasLimit, the faster their outbound transaction will be executed.

However, there is no minimum gas limit check, therefore no incentive for users to pay for the gas price, allowing them to only pay for the PROTOCOL_FLAT_FEE.

Let's follow what happens when a user specifies gasLimit = 0 in GatewayZEVM::call, but also note that the same applies to GatewayZEVM::withdrawAndCall.

GatewayZEVM.sol#L247-L267
```javascript
function call(
        bytes memory receiver,
        address zrc20,
        bytes calldata message,
@>      uint256 gasLimit,
        RevertOptions calldata revertOptions
    )
        external
        nonReentrant
        whenNotPaused
    {
        if (receiver.length == 0) revert ZeroAddress();
        if (message.length == 0) revert EmptyMessage();

@>      (address gasZRC20, uint256 gasFee) = IZRC20(zrc20).withdrawGasFeeWithGasLimit(gasLimit);
        if (!IZRC20(gasZRC20).transferFrom(msg.sender, FUNGIBLE_MODULE_ADDRESS, gasFee)) {
            revert GasFeeTransferFailed();
        }

        emit Called(msg.sender, zrc20, receiver, message, gasLimit, revertOptions);
    }
```
Looking at the implementation of ZRC20::withdrawGasFeeWithGasLimit:

ZRC20.sol#L281-L291
```javascript
function withdrawGasFeeWithGasLimit(uint256 gasLimit) public view override returns (address, uint256) {
        address gasZRC20 = ISystem(SYSTEM_CONTRACT_ADDRESS).gasCoinZRC20ByChainId(CHAIN_ID);
        if (gasZRC20 == address(0)) revert ZeroGasCoin();

        uint256 gasPrice = ISystem(SYSTEM_CONTRACT_ADDRESS).gasPriceByChainId(CHAIN_ID);
        if (gasPrice == 0) {
            revert ZeroGasPrice();
        }
@>      uint256 gasFee = gasPrice * gasLimit + PROTOCOL_FLAT_FEE;
        return (gasZRC20, gasFee);
    }
```

If gasLimit = 0, then gasFee = PROTOCOL_FLAT_FEE. The gasPrice implementation is completely redundant and allows users to avoid paying for the gas price.

The user will only have to pay for the PROTOCOL_FLAT_FEE in this case.

This differs from GatewayZEVM::withdraw, which uses the GAS_LIMIT defined in ZRC20:

GatewayZEVM.sol#L91-L94
```javascript
function _withdrawZRC20(uint256 amount, address zrc20) internal returns (uint256) {
        // Use gas limit from zrc20
        return _withdrawZRC20WithGasLimit(amount, zrc20, IZRC20(zrc20).GAS_LIMIT());
    }
```

The following PoC displays how a user is able to specify gas limit = 0 to avoid paying the gas price and only pay for the protocol fee (if there is one set). Recall that this problem exists in both call and withdrawAndCall.

Coded PoC
```javascript
Add the following to the test/ folder and run forge test --mt testCallWithZeroGasLimit -vv

// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";

import "./utils/SystemContract.sol";

import "./utils/TestUniversalContract.sol";

import "./utils/WZETA.sol";

import "../contracts/zevm/GatewayZEVM.sol";
import "../contracts/zevm/ZRC20.sol";
import "../contracts/zevm/interfaces/IGatewayZEVM.sol";
import "../contracts/zevm/interfaces/IZRC20.sol";
import { Upgrades } from "openzeppelin-foundry-upgrades/Upgrades.sol";

contract GatewayTest is Test, IGatewayZEVMEvents, IGatewayZEVMErrors {
    address payable proxy;
    GatewayZEVM gateway;
    ZRC20 zrc20;
    WETH9 zetaToken;
    SystemContract systemContract;
    TestUniversalContract testUniversalContract;
    address owner;
    address addr1;
    address fungibleModule;
    RevertOptions revertOptions;

    error ZeroAddress();
    error LowBalance();

    function setUp() public {
        owner = address(this);
        addr1 = address(0x1234);

        zetaToken = new WETH9();

        proxy = payable(
            Upgrades.deployUUPSProxy(
                "GatewayZEVM.sol", abi.encodeCall(GatewayZEVM.initialize, (address(zetaToken), owner))
            )
        );
        gateway = GatewayZEVM(proxy);

        fungibleModule = gateway.FUNGIBLE_MODULE_ADDRESS();
        testUniversalContract = new TestUniversalContract();

        vm.startPrank(fungibleModule);
        systemContract = new SystemContract(address(0), address(0), address(0));
        zrc20 = new ZRC20("TOKEN", "TKN", 18, 1, CoinType.Gas, 0, address(systemContract), address(gateway));
        systemContract.setGasCoinZRC20(1, address(zrc20));
        systemContract.setGasPrice(1, 1);
        vm.deal(fungibleModule, 1_000_000_000);
        zetaToken.deposit{ value: 10 }();
        zetaToken.approve(address(gateway), 10);
        zrc20.deposit(owner, 100_000);
        zrc20.updateProtocolFlatFee(100);
        vm.stopPrank();

        vm.startPrank(owner);
        zrc20.approve(address(gateway), 100_000);
        zetaToken.deposit{ value: 10 }();
        zetaToken.approve(address(gateway), 10);
        vm.stopPrank();

        revertOptions = RevertOptions({
            revertAddress: address(0x321),
            callOnRevert: true,
            abortAddress: address(0x321),
            revertMessage: "",
            onRevertGasLimit: 0
        });
    }

    function testCallWithZeroGasLimit() public {
        bytes memory message = abi.encodeWithSignature("hello(address)", addr1);
        vm.expectEmit(true, true, true, true, address(gateway));
        uint256 ownerBalanceBefore = zrc20.balanceOf(owner);

        emit Called(owner, address(zrc20), abi.encodePacked(addr1), message, 0, revertOptions);
        gateway.call(abi.encodePacked(addr1), address(zrc20), message, 0, revertOptions); // gas limit set to 0, so user only has to pay protocol fee instead of gas price
        
        uint256 ownerBalanceAfter = zrc20.balanceOf(owner);
        uint256 protocol_fee = IZRC20(zrc20).PROTOCOL_FLAT_FEE();
        console.log("fee: ", protocol_fee);
        assertEq(ownerBalanceBefore - protocol_fee, ownerBalanceAfter);
    }
}
```

Console Output
```text
Ran 1 test for test/GatewayTest.t.sol:GatewayTest [PASS] testCallWithZeroGasLimit() (gas: 109935) Logs: fee: 100

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 3.11s (247.70µs CPU time)

Ran 1 test suite in 3.11s (3.11s CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

## Impact

ZRC20 gas price redundant, loss for the protocol and for FUNGIBLE_MODULE_ADDRESS who will lose funds from paying for the gas of Outbound ZetaChain transactions, without receiving gas payments from the ZetaChain Inbound transaction.

## Recommendation

The following is just my suggestion, if the protocol's intention is that gas limit must always be <= IZRC20(zrc20).GAS_LIMIT(), then my exact recommendation will not work, however the intention is to add a minimum gas limit check.

It is recommended to incorporate a check that the gas limit defined must be >= IZRC20(zrc20).GAS_LIMIT() in withdrawAndCall and call functions.
```diff
function withdrawAndCall(
        bytes memory receiver,
        uint256 amount,
        address zrc20,
        bytes calldata message,
        uint256 gasLimit,
        RevertOptions calldata revertOptions
    )
        external
        nonReentrant
        whenNotPaused
    {
        if (receiver.length == 0) revert ZeroAddress();
        if (amount == 0) revert InsufficientZRC20Amount();
+       require(gasLimit >= IZRC20(zrc20).GAS_LIMIT(), "Gas limit too low");
        uint256 gasFee = _withdrawZRC20WithGasLimit(amount, zrc20, gasLimit);
        emit Withdrawn(
            msg.sender,
            0,
            receiver,
            zrc20,
            amount,
            gasFee,
            IZRC20(zrc20).PROTOCOL_FLAT_FEE(),
            message,
            gasLimit,
            revertOptions
        );
    }
function call(
        bytes memory receiver,
        address zrc20,
        bytes calldata message,
        uint256 gasLimit,
        RevertOptions calldata revertOptions
    )
        external
        nonReentrant
        whenNotPaused
    {
        if (receiver.length == 0) revert ZeroAddress();
        if (message.length == 0) revert EmptyMessage();
+       require(gasLimit >= IZRC20(zrc20).GAS_LIMIT(), "Gas limit too low");
        (address gasZRC20, uint256 gasFee) = IZRC20(zrc20).withdrawGasFeeWithGasLimit(gasLimit);
        if (!IZRC20(gasZRC20).transferFrom(msg.sender, FUNGIBLE_MODULE_ADDRESS, gasFee)) {
            revert GasFeeTransferFailed();
        }
        emit Called(msg.sender, zrc20, receiver, message, gasLimit, revertOptions);
    }
```

## [M-3] Malicious user can call GatewayEVM::depositAndCall with dust amount to waste gas for the Fungible account

## Summary

During a `GatewayEVM::depositAndCall` call, users transfer ETH to the TSS address, where an inbound event will be initiated. In the outbound event, the Fungible account will mint the user ZRC20 tokens on ZetaChain, corresponding to the ETH deposited, and will also make an external call on behalf of the user.

GatewayEVM.sol#L257-L275
```javascript
function depositAndCall(
        address receiver,
        bytes calldata payload,
        RevertOptions calldata revertOptions
    )
        external
        payable
        whenNotPaused
        nonReentrant
    {
@>      if (msg.value == 0) revert InsufficientETHAmount();
        if (receiver == address(0)) revert ZeroAddress();

        (bool deposited,) = tssAddress.call{ value: msg.value }("");

        if (!deposited) revert DepositFailed();

        emit Deposited(msg.sender, receiver, msg.value, address(0), payload, revertOptions);
    }
```
A check is incorporated to ensure that user cannot deposit an amount of 0. However, a user can still deposit dust amount (i.e., 1 wei).

Imagine a scenario where the outgoing inbound events are filled with a deposited amount of 1 wei. The fungible account will have to constantly mint 1wei of ZRC20 token to the account on ZetaChain, while making an external call for the user:

GatewayZEVM.sol#L310-L327)
```javascript
function depositAndCall(
        zContext calldata context,
        address zrc20,
        uint256 amount,
        address target,
        bytes calldata message
    )
        external
        onlyFungible
        whenNotPaused
    {
        if (zrc20 == address(0) || target == address(0)) revert ZeroAddress();
        if (amount == 0) revert InsufficientZRC20Amount();
        if (target == FUNGIBLE_MODULE_ADDRESS || target == address(this)) revert InvalidTarget();

        if (!IZRC20(zrc20).deposit(target, amount)) revert ZRC20DepositFailed();
        UniversalContract(target).onCrossChainCall(context, zrc20, amount, message);
    }
```
This will be more gas intensive for the Fungible account, causing a loss of funds.

## Impact

Loss of funds for the Fungible account, ZetaChain spammed with inbound events with dust amount.

## Recommendation

Incorporate a minimum deposit check that is greater than 0, and do the same for other deposit functions.


## [M-4] GatewayZEVM is missing functionality to refund gasZRC20 tokens for reverted transactions

## Summary

The following is the flow of cross chain interaction: inbound tx -> emit inbound event -> observer set generates outbound tx -> emit outbound event -> cctx finalized.

There are cases where once the inbound transaction is confirmed, the outbound transaction can revert. Unless the protocol refunds the user in this case, all funds will be lost.

Competition docs explain the flow of revert management, and sponsors on discord have confirmed that the refund/revert flow happens on the source chain.

For example, if a user decides to withdraw their ZRC20 tokens on ZetaChain, they must burn their ZRC20 tokens and send gasZRC20 to the Fungible account via a call to GatewayZEVM::withdraw, and should receive ERC20 tokens on the destination chain by the TSS address. In case the call by the TSS address fails, the Fungible account will refund (via minting) the same amount of ZRC20 back to the user on ZetaChain.

In addition, if a user calls call to call a smart contract on an external chain without asset transfer, they must transfer gasZRC20 to the Fungible account. If this call reverts, the fungible account calls executeRevert.

The problem is that the gasZRC20 spent is not refunded in any of these cases, causing a loss of funds.

## Details

Let's see what happens when a user withdraws ZRC20 tokens. A call to GatewayZEVM::withdraw or GatewayZEVM::withdrawAndCall will be made, where the ZRC20 tokens are burned on ZetaChain, and gasZRC20 tokens are sent to the Fungible account. The TSS address will proceed to transfer ERC20 tokens to the user on the destination chain. If this transaction reverts, then the Fungible account will proceed to mint the user new ZRC20 tokens, depending on which function the user originally called.

If the user's call to GatewayZEVM::withdraw failed, then the fungible account will proceed to call GatewayZEVM::deposit to refund (via minting) the amount of ZRC20 that was burned by the user.
If the user's call to GatewayZEVM::withdrawAndCall failed, then the fungible account will proceed to call GatewayZEVM::depositAndRevert to refund (via minting) the amount of ZRC20 that was burned by the user.
If the user's call to GatewayZEVM::call failed, then the fungible account will proceed to call GatewayZEVM::executeRevert.
Here is the flow:

GatewayZEVM.sol#L126-L157
```javascript
/// @notice Withdraw ZRC20 tokens to an external chain.
    /// @param receiver The receiver address on the external chain.
    /// @param amount The amount of tokens to withdraw.
    /// @param zrc20 The address of the ZRC20 token.
    /// @param revertOptions Revert options.
    function withdraw(
        bytes memory receiver,
        uint256 amount,
        address zrc20,
        RevertOptions calldata revertOptions
    )
        external
        nonReentrant
        whenNotPaused
    {
        if (receiver.length == 0) revert ZeroAddress();
        if (amount == 0) revert InsufficientZRC20Amount();

@>      uint256 gasFee = _withdrawZRC20(amount, zrc20);
        emit Withdrawn(
            msg.sender,
            0,
            receiver,
            zrc20,
            amount,
            gasFee,
            IZRC20(zrc20).PROTOCOL_FLAT_FEE(),
            "",
            IZRC20(zrc20).GAS_LIMIT(),
            revertOptions
        );
    }
```
A call to _withdrawZRC20 is made, which calls _withdrawZRC20WithGasLimit:

GatewayZEVM.sol#L91-L114
```javascript
function _withdrawZRC20(uint256 amount, address zrc20) internal returns (uint256) {
        // Use gas limit from zrc20
        return _withdrawZRC20WithGasLimit(amount, zrc20, IZRC20(zrc20).GAS_LIMIT());
    }

    /// @dev Internal function to withdraw ZRC20 tokens with gas limit.
    /// @param amount The amount of tokens to withdraw.
    /// @param zrc20 The address of the ZRC20 token.
    /// @param gasLimit Gas limit.
    /// @return The gas fee for the withdrawal.
    function _withdrawZRC20WithGasLimit(uint256 amount, address zrc20, uint256 gasLimit) internal returns (uint256) {
        (address gasZRC20, uint256 gasFee) = IZRC20(zrc20).withdrawGasFeeWithGasLimit(gasLimit);
@>      if (!IZRC20(gasZRC20).transferFrom(msg.sender, FUNGIBLE_MODULE_ADDRESS, gasFee)) {
            revert GasFeeTransferFailed();
        }

        if (!IZRC20(zrc20).transferFrom(msg.sender, address(this), amount)) {
            revert ZRC20TransferFailed();
        }

@>      if (!IZRC20(zrc20).burn(amount)) revert ZRC20BurnFailed();

        return gasFee;
    }
```
We can observe that gasZRC20 is sent to the Fungible account, where zrc20 is burned. This will finalize the inbound transaction, where the TSS must transfer the user ERC20 on the destination chain. However, that transaction can revert. The Fungible account will refund the user as follows:

GatewayZEVM.sol#L273-L280
```javascript
function deposit(address zrc20, uint256 amount, address target) external onlyFungible whenNotPaused {
        if (zrc20 == address(0) || target == address(0)) revert ZeroAddress();
        if (amount == 0) revert InsufficientZRC20Amount();

        if (target == FUNGIBLE_MODULE_ADDRESS || target == address(this)) revert InvalidTarget();

        if (!IZRC20(zrc20).deposit(target, amount)) revert ZRC20DepositFailed();
    }
```
GatewayZEVM.sol#L366-L382
```javascript
function depositAndRevert(
        address zrc20,
        uint256 amount,
        address target,
        RevertContext calldata revertContext
    )
        external
        onlyFungible
        whenNotPaused
    {
        if (zrc20 == address(0) || target == address(0)) revert ZeroAddress();
        if (amount == 0) revert InsufficientZRC20Amount();
        if (target == FUNGIBLE_MODULE_ADDRESS || target == address(this)) revert InvalidTarget();

        if (!IZRC20(zrc20).deposit(target, amount)) revert ZRC20DepositFailed();
        UniversalContract(target).onRevert(revertContext);
    }
```
These calls will refund the user ZRC20 by minting them the amount that was burned. deposit is called if the user initiated withdraw, whereas depositAndRevert is called if the user initiated withdrawAndCall. This can also be observed in the diagram provided in the competition docs.

However, we can see that the gasZRC20 that was sent to the Fungible account is not refunded. This will be a loss for users, since they will lose that amount despite their transaction not executing.

This is also the case if GatewayZEVM::call reverts:

GatewayZEVM.sol#L241-L267
```javascript
/// @notice Call a smart contract on an external chain without asset transfer.
    /// @param receiver The receiver address on the external chain.
    /// @param zrc20 Address of zrc20 to pay fees.
    /// @param message The calldata to pass to the contract call.
    /// @param gasLimit Gas limit.
    /// @param revertOptions Revert options.
    function call(
        bytes memory receiver,
        address zrc20,
        bytes calldata message,
        uint256 gasLimit,
        RevertOptions calldata revertOptions
    )
        external
        nonReentrant
        whenNotPaused
    {
        if (receiver.length == 0) revert ZeroAddress();
        if (message.length == 0) revert EmptyMessage();

@>      (address gasZRC20, uint256 gasFee) = IZRC20(zrc20).withdrawGasFeeWithGasLimit(gasLimit);
@>      if (!IZRC20(gasZRC20).transferFrom(msg.sender, FUNGIBLE_MODULE_ADDRESS, gasFee)) {
            revert GasFeeTransferFailed();
        }

        emit Called(msg.sender, zrc20, receiver, message, gasLimit, revertOptions);
    }
```
If this reverts on the external chain, then the fungible address will call GatewayZEVM::executeRevert:

GatewayZEVM.sol#L355-L359
```javascript
function executeRevert(address target, RevertContext calldata revertContext) external onlyFungible whenNotPaused {
        if (target == address(0)) revert ZeroAddress();

        UniversalContract(target).onRevert(revertContext);
    }
```
We can see the gasZRC20 tokens spent are not refunded.

## Impact

Loss of funds for users since gasZRC20 tokens are spent with no refund.

## Recommendation

Refund the user gasZRC20 in addition to ZRC20. Consider adding functionality to existing refund functions, where the fungible account can specify the gas limit to refund.

```diff
-   function deposit(address zrc20, uint256 amount, address target) external onlyFungible whenNotPaused {
+   function deposit(address zrc20, uint256 amount, address target, uint256 gasRefund) external onlyFungible whenNotPaused {
        if (zrc20 == address(0) || target == address(0)) revert ZeroAddress();
        if (amount == 0) revert InsufficientZRC20Amount();
        if (target == FUNGIBLE_MODULE_ADDRESS || target == address(this)) revert InvalidTarget();
        if (!IZRC20(zrc20).deposit(target, amount)) revert ZRC20DepositFailed();
+       if (gasRefund != 0){       
+           (address gasZRC20, uint256 gasFee) = IZRC20(zrc20).withdrawGasFeeWithGasLimit(gasRefund);
+           if (!IZRC20(gasZRC20).transferFrom(msg.sender, target, gasFee)) {
+               revert GasFeeTransferFailed();
+           }
+       }
    }
function depositAndRevert(
        address zrc20,
        uint256 amount,
        address target,
+       uint256 gasRefund,
        RevertContext calldata revertContext
    )
        external
        onlyFungible
        whenNotPaused
    {
        if (zrc20 == address(0) || target == address(0)) revert ZeroAddress();
        if (amount == 0) revert InsufficientZRC20Amount();
        if (target == FUNGIBLE_MODULE_ADDRESS || target == address(this)) revert InvalidTarget();
        if (!IZRC20(zrc20).deposit(target, amount)) revert ZRC20DepositFailed();
        UniversalContract(target).onRevert(revertContext);
+       if (gasRefund != 0){       
+           (address gasZRC20, uint256 gasFee) = IZRC20(zrc20).withdrawGasFeeWithGasLimit(gasRefund);
+           if (!IZRC20(gasZRC20).transferFrom(msg.sender, target, gasFee)) {
+               revert GasFeeTransferFailed();
+           }
+       }
    }
-   function executeRevert(address target, RevertContext calldata revertContext) external onlyFungible whenNotPaused {
+   function executeRevert(address target, address zrc20, RevertContext calldata revertContext, uint256 gasRefund) external onlyFungible whenNotPaused {
        if (target == address(0)) revert ZeroAddress();
+       if (gasRefund != 0){       
+           (address gasZRC20, uint256 gasFee) = IZRC20(zrc20).withdrawGasFeeWithGasLimit(gasRefund);
+           if (!IZRC20(gasZRC20).transferFrom(msg.sender, target, gasFee)) {
+               revert GasFeeTransferFailed();
+           }
+       }
        UniversalContract(target).onRevert(revertContext);
    }
```

## [M-5] Users can lose funds if calling GatewayZEVM::call or GatewayZEVM::withdrawAndCall to Solana

## Summary

GatewayZEVM::call and GatewayZEVM::withdrawAndCall allows users to make external calls by paying with gasZRC20, and also withdrawing ZRC20 tokens for the latter option.

GatewayZEVM.sol#L241-L267
```javascript
/// @notice Call a smart contract on an external chain without asset transfer.
    /// @param receiver The receiver address on the external chain.
    /// @param zrc20 Address of zrc20 to pay fees.
    /// @param message The calldata to pass to the contract call.
    /// @param gasLimit Gas limit.
    /// @param revertOptions Revert options.
    function call(
        bytes memory receiver,
        address zrc20,
        bytes calldata message,
        uint256 gasLimit,
        RevertOptions calldata revertOptions
    )
        external
        nonReentrant
        whenNotPaused
    {
        if (receiver.length == 0) revert ZeroAddress();
        if (message.length == 0) revert EmptyMessage();

        (address gasZRC20, uint256 gasFee) = IZRC20(zrc20).withdrawGasFeeWithGasLimit(gasLimit);
@>      if (!IZRC20(gasZRC20).transferFrom(msg.sender, FUNGIBLE_MODULE_ADDRESS, gasFee)) {
            revert GasFeeTransferFailed();
        }

        emit Called(msg.sender, zrc20, receiver, message, gasLimit, revertOptions);
    }
```
We can observe the caller must pay a fee for the transaction, sent to the Fungible account. This is also the case for withdrawAndCall.

However, currently the Solana gateway does not have any functionality to make external calls to the user specified address, it can only invoke a token transfer.

This can observed in #1, and #2.

In addition, this doesn't fall under revert management (where the observer initiates a "refund" if the transaction on the destination chain reverts) because there is no external call being made, so there is no revert happening. The observer will have no reason to conclude that the transaction has not been successful, therefore funds will be lost.

## Impact

Loss of funds, gasZRC20 spent that are lost.

## Recommendation

It is recommended to implement the ability for the tss address to make external calls in lib.rs

## [M-6] TSS_ROLE cannot be changed by admin in ERC20Custody and Connector contracts

## Summary

The competition docs state under Access Control section that "tss address with TSS_ROLE set on deployment, can be changed by admin" for contracts ERC20Custody, ZetaConnectorNative, and ZetaConnectorNonNative.

However, there is no functionality for this within the contracts, and the contracts are not upgradeable either. This contradicts the intended design. This is also stated for the GatewayZEVM contract, however that contract is upgradeable, so it is still possible to change the tss address. If the tss address is changed in GatewayZEVM, it still cannot be changed in ERC20Custody or the connector contracts.

## Impact

Admin cannot change tss address, it will remain permanently, and can conflict with the upgradeability of Gateway contracts that can change the tss address.

## Recommendation

Add functionality with admin access control that can update the TSS_ROLE to a new address.
