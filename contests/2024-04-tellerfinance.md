# Teller Finance

[Teller](https://audits.sherlock.xyz/contests/295) is a non-custodial lending book that enables time-based loans. The protocol supports any ERC20 (token) or ERC721 / ERC1155 (NFT) as collateral, with no margin liquidations for the duration of a loan. Teller is live on Ethereum, Base, Arbitrum, and Polygon.

## Audit Findings Summary

| ID | Title | Severity |
|----|----------|----------|
| [H-1](#h-1-lendercommitgroup_smartacceptfundsforacceptbid-will-not-revert-if-insufficient-collateral-is-provided) | LenderCommitGroup_Smart::acceptFundsForAcceptBid will not revert if insufficient collateral is provided | High |
| [H-2](#h-2-lendercommitmentgroup_smartliquidatedefaultedloanwithincentive-does-not-send-collateral-to-the-caller) | LenderCommitmentGroup_Smart::liquidateDefaultedLoanWithIncentive does not send collateral to the caller | High |
| [H-3](#h-3-multiple-contracts-incompatible-with-usdt) | Multiple contracts incompatible with USDT | High |
| [M-1](#m-1-lendercommitmentgroup-pools-will-have-incorrect-exchange-rate-when-fee-on-transfer-tokens-are-used) | LenderCommitmentGroup pools will have incorrect exchange rate when fee-on-transfer tokens are used | Medium |
---

## [H-1] LenderCommitGroup_Smart::acceptFundsForAcceptBid will not revert if insufficient collateral is provided

## Summary

LenderCommitmentGroup_Smart is a contract that acts as it's own loan committment, which has liquidity pools with principal token and collateral token. Users can deposit principal tokens in exchange for share tokens.

Due to an issue regarding decimal precision, the check to ensure borrower has specified sufficient amount of collateral will always pass, allowing them to borrow far more than they should for the amount of collateral specified.

## Vulnerability Detail

LenderCommitmentGroup_Smart::acceptFundsForAcceptBid #L336
```javascript
   function acceptFundsForAcceptBid(
        address _borrower,
        uint256 _bidId,
        uint256 _principalAmount,
        uint256 _collateralAmount,
        address _collateralTokenAddress,
        uint256 _collateralTokenId,
        uint32 _loanDuration,
        uint16 _interestRate
    ) external onlySmartCommitmentForwarder whenNotPaused {
        require(
            _collateralTokenAddress == address(collateralToken),
            "Mismatching collateral token"
        );
        
        .
        .
        .

        //this is expanded by 10**18
@>      uint256 requiredCollateral = getCollateralRequiredForPrincipalAmount(
            _principalAmount
        );

@>      require(
            (_collateralAmount * STANDARD_EXPANSION_FACTOR) >=
                requiredCollateral,
            "Insufficient Borrower Collateral"
        );
    }
```

If we follow the flow of getCollateralRequiredForPrincipalAmount, we see the following:
```javascript
    //this result is expanded by UNISWAP_EXPANSION_FACTOR
    function _getUniswapV3TokenPairPrice(
        uint32 _twapInterval
    ) internal view returns (uint256) {
        // represents the square root of the price of token1 in terms of token0

        uint160 sqrtPriceX96 = getSqrtTwapX96(_twapInterval);

@>      //this output is the price ratio expanded by 1e18
        return _getPriceFromSqrtX96(sqrtPriceX96);
    }
```

Dev comments implicate that the assumption is that the output of the ratio is expanded by 1e18. However, this is not the case:
```javascript
    //this result is expanded by UNISWAP_EXPANSION_FACTOR
    function _getPriceFromSqrtX96(
        uint160 _sqrtPriceX96
    ) internal pure returns (uint256 price_) {
        uint256 priceX96 = (uint256(_sqrtPriceX96) * uint256(_sqrtPriceX96)) /
            (2 ** 96);

        // sqrtPrice is in X96 format so we scale it down to get the price
        // Also note that this price is a relative price between the two tokens in the pool
        // It's not a USD price
        price_ = priceX96;
    }
```
We can see that there is no expanding by 1e18. Now, looking back at acceptFundsForAcceptBid():

requiredCollateral is the amount of collateral that the borrower must provide for the amount of principal they would like to borrow. The dev comments suggest that the amount is expanded by 1e18, but that is not true, It simply represents the amount of collateral token (i.e, amount * 10**18).

Lets say the collateral is WETH, which has 18 decimals. The _collateralAmount parameter will be in 18 decimals already, but here we multiply by STANDARD_EXPANSION_FACTOR which is equal to 1e18. This will expand the decimals that will far exceed the decimals of requiredCollateral, therefore always passing the require check.

Lets say Bob specifies 1 WETH for _collateralAmount => _collateralAmount = 1e18.
requiredCollateral is 5 WETH => requiredCollateral = 5e18

_collateralAmount * STANDARD_EXPANSION_FACTOR = 1e18 * 1e18 = 1e36 > 5e18.

Here, where the collateral specified is far less than amount required, passed the check, allowing Bob to borrow much more tokens for little collateral.

## Impact

Borrower users can borrow far more than they should be able to for the amount of collateral provided. Lender users suffer.

## Code Snippet

https://github.com/sherlock-audit/2024-04-teller-finance/blob/main/teller-protocol-v2-audit-2024/packages/contracts/contracts/LenderCommitmentForwarder/extensions/LenderCommitmentGroup/LenderCommitmentGroup_Smart.sol#L336

## Tools Used
Manual Review.

## Recommendation
Change the target address when routing the collectionReferrerShare

Remove the STANDARD_EXPANSION_FACTOR from the multiplication or expand by 1e18 as intended.

## [H-2] LenderCommitmentGroup_Smart::liquidateDefaultedLoanWithIncentive does not send collateral to the caller

## Summary

LenderCommitmentGroup_Smart is a contract that acts as it's own loan committment, which has liquidity pools with principal token and collateral token.

The docs of the LenderCommitmentGroup_Smart.sol states "If the borrower defaults on a loan, for 24 hours a liquidation auction is automatically conducted by this smart contract in order to incentivize a liquidator to take the collateral tokens in exchange for principal tokens."

The intention is that, after a certain amount of time has passed, anyone can call liquidateDefaultedLoanWithIncentive to pay the loan in return for the collateral. The problem is that the caller does not receive the collateral, and is instead issued to the lender address.

## Vulnerability Detail

LenderCommitmentGroup_Smart::liquidateDefaultedLoanWithIncentive
```javascript
   function liquidateDefaultedLoanWithIncentive(
        uint256 _bidId,
        int256 _tokenAmountDifference
    ) public bidIsActiveForGroup(_bidId) {
        uint256 amountDue = getAmountOwedForBid(_bidId, false);

        uint256 loanDefaultedTimeStamp = ITellerV2(TELLER_V2)
            .getLoanDefaultTimestamp(_bidId);

        int256 minAmountDifference = getMinimumAmountDifferenceToCloseDefaultedLoan(
                amountDue,
                loanDefaultedTimeStamp
            );

        require(
            _tokenAmountDifference >= minAmountDifference,
            "Insufficient tokenAmountDifference"
        );

        if (_tokenAmountDifference > 0) {
            //this is used when the collateral value is higher than the principal (rare)
            //the loan will be completely made whole and our contract gets extra funds too
            uint256 tokensToTakeFromSender = abs(_tokenAmountDifference);

            IERC20(principalToken).transferFrom(
                msg.sender,
                address(this),
                amountDue + tokensToTakeFromSender
            );

            tokenDifferenceFromLiquidations += int256(tokensToTakeFromSender);

            totalPrincipalTokensRepaid += amountDue;
        } else {
            uint256 tokensToGiveToSender = abs(_tokenAmountDifference);

            IERC20(principalToken).transferFrom(
                msg.sender,
                address(this),
                amountDue - tokensToGiveToSender
            );

            tokenDifferenceFromLiquidations -= int256(tokensToGiveToSender);

            totalPrincipalTokensRepaid += amountDue;
        }

        //this will give collateral to the caller
        // @audit this doesn't give collateral to the caller, msg.sender is unused
@>      ITellerV2(TELLER_V2).lenderCloseLoanWithRecipient(_bidId, msg.sender);
    }
```
Following the flow of the function call:

TellerV2::lenderCloseLoanWithRecipient
```javascript
    function lenderCloseLoanWithRecipient(
        uint256 _bidId,
        address _collateralRecipient
    ) external {
 @>     _lenderCloseLoanWithRecipient(_bidId, _collateralRecipient);
    }
```


```javascript
    // @audit `_collateralRecipient` is unused
    function _lenderCloseLoanWithRecipient(
        uint256 _bidId,
        address _collateralRecipient
    ) internal acceptedLoan(_bidId, "lenderClaimCollateral") {
        require(isLoanDefaulted(_bidId), "Loan must be defaulted.");

        Bid storage bid = bids[_bidId];
        bid.state = BidState.CLOSED;

        address sender = _msgSenderForMarket(bid.marketplaceId);
        require(sender == bid.lender, "only lender can close loan");

@>      collateralManager.lenderClaimCollateral(_bidId);

        emit LoanClosed(_bidId);
    }
```
CollateralManager::lenderClaimCollateral

```javascript
    function lenderClaimCollateral(uint256 _bidId) external onlyTellerV2 {
        if (isBidCollateralBacked(_bidId)) {
            BidState bidState = tellerV2.getBidState(_bidId);

            require(
                bidState == BidState.CLOSED,
                "Loan has not been liquidated"
            );

            // @audit here we can see that the loan lender address is passed for the withdrawal amount
@>          _withdraw(_bidId, tellerV2.getLoanLender(_bidId));
            emit CollateralClaimed(_bidId);
        }
    }
```

Following through with _withdraw, tellerV2.getLoanLender(_bidId) is the address that will receive the amount, not the original caller.

## Impact

Loss of funds for the caller of liquidateDefaultedLoanWithIncentive, who did not receive the collateral after paying off the loan.

## Code Snippet

https://github.com/sherlock-audit/2024-04-teller-finance/blob/main/teller-protocol-v2-audit-2024/packages/contracts/contracts/LenderCommitmentForwarder/extensions/LenderCommitmentGroup/LenderCommitmentGroup_Smart.sol#L471

https://github.com/sherlock-audit/2024-04-teller-finance/blob/main/teller-protocol-v2-audit-2024/packages/contracts/contracts/TellerV2.sol#L738-L774

https://github.com/sherlock-audit/2024-04-teller-finance/blob/main/teller-protocol-v2-audit-2024/packages/contracts/contracts/CollateralManager.sol#L416

## Tools Used
Manual Review.

## Recommendation

Ensure that _collateralRecipient receives the collateral.

## [H-3] Multiple contracts incompatible with USDT

## Summary

The protocol states "We are allowing any standard token that would be compatible with Uniswap V3 to work with our codebase".

However, due to use of IERC20Upgradeable.approve() and IERC20Upgradeable.transfer() in FlashRolloverLoan_G5, and IERC20.transferFrom in LenderCommitmentGroup_Smart, these contracts are incompatible with USDT.

## Vulnerability Detail

The functions mentioned above all return a bool, however USDT on mainnet does not.

Function signatures don't match and therefore will revert.

## Impact

USDT incompatible with contracts mentioned above.

## Code Snippet

https://github.com/sherlock-audit/2024-04-teller-finance/blob/main/teller-protocol-v2-audit-2024/packages/contracts/contracts/LenderCommitmentForwarder/extensions/LenderCommitmentGroup/LenderCommitmentGroup_Smart.sol#L445-L463

https://github.com/sherlock-audit/2024-04-teller-finance/blob/main/teller-protocol-v2-audit-2024/packages/contracts/contracts/LenderCommitmentForwarder/extensions/FlashRolloverLoan_G5.sol#L111

https://github.com/sherlock-audit/2024-04-teller-finance/blob/main/teller-protocol-v2-audit-2024/packages/contracts/contracts/LenderCommitmentForwarder/extensions/FlashRolloverLoan_G5.sol#L205

https://github.com/sherlock-audit/2024-04-teller-finance/blob/main/teller-protocol-v2-audit-2024/packages/contracts/contracts/LenderCommitmentForwarder/extensions/FlashRolloverLoan_G5.sol#L194

## Tools Used
Manual Review.

## Recommendation
Incorporate openzeppelin's SafeERC20

## [M-1] LenderCommitmentGroup pools will have incorrect exchange rate when fee-on-transfer tokens are used

## Summary

LenderCommitGroup_Smart contract incorporates internal accounting for the amount of tokens deposited, withdrawn, etc. The problem is that if one of the pools has a fee-on-transfer token, the accounting is not adjusted. This will create inflated accountings of the tokens within the pool, and impact the exchange rate.

## Vulnerability Detail

LenderCommitmentGroup_Smart is a contract that acts as it's own loan committment, which has liquidity pools with principal token and collateral token. Users can deposit principal tokens in exchange for share tokens.

Here is the flow of depositing principal tokens for shares

LenderCommitmentGroup_Smart::addPrincipalToCommitmentGroup
```javascript
    function addPrincipalToCommitmentGroup(
        uint256 _amount,
        address _sharesRecipient
    ) external returns (uint256 sharesAmount_) {
        
        // @audit if token is Fee-on-transfer, `_amount` transferred will be less
        principalToken.transferFrom(msg.sender, address(this), _amount);

@>      sharesAmount_ = _valueOfUnderlying(_amount, sharesExchangeRate());

        // @audit this will be inflated
        totalPrincipalTokensCommitted += _amount;

        // @audit Bob is minted shares dependent on original amount, not amount after transfer
        poolSharesToken.mint(_sharesRecipient, sharesAmount_);
    }
    function sharesExchangeRate() public view virtual returns (uint256 rate_) {
        //@audit As more FOT tokens are deposited, this value becomes inflated
        uint256 poolTotalEstimatedValue = getPoolTotalEstimatedValue();

        // @audit EXCHANGE_RATE_EXPANSION_FACTOR = 1e36
        if (poolSharesToken.totalSupply() == 0) {
            return EXCHANGE_RATE_EXPANSION_FACTOR; // 1 to 1 for first swap
        }

        rate_ =
            (poolTotalEstimatedValue * EXCHANGE_RATE_EXPANSION_FACTOR) /
            poolSharesToken.totalSupply();
    }
    function _valueOfUnderlying(
        uint256 amount,
        uint256 rate
    ) internal pure returns (uint256 value_) {
        if (rate == 0) {
            return 0;
        }

        value_ = (amount * EXCHANGE_RATE_EXPANSION_FACTOR) / rate;
    }
```

As you can see, the original _amount entered is used to not only issue the shares, but to keep track of the amount pool has:
```javascript
    function getPoolTotalEstimatedValue()
        public
        view
        returns (uint256 poolTotalEstimatedValue_)
    {
        // @audit This will be inflated
        int256 poolTotalEstimatedValueSigned = int256(
            totalPrincipalTokensCommitted
        ) +
            int256(totalInterestCollected) +
            int256(tokenDifferenceFromLiquidations) -
            int256(totalPrincipalTokensWithdrawn);

        poolTotalEstimatedValue_ = poolTotalEstimatedValueSigned > int256(0)
            ? uint256(poolTotalEstimatedValueSigned)
            : 0;
    }
```
If poolTotalEstimatedValue is inflated, then the exchange rate will be incorrect.

## Impact

As mentioned above, incorrect exchange rate calculation. Users will not receive the correct amount of shares/PT when withdrawing/depositing

## Code Snippet

https://github.com/sherlock-audit/2024-04-teller-finance/blob/main/teller-protocol-v2-audit-2024/packages/contracts/contracts/LenderCommitmentForwarder/extensions/LenderCommitmentGroup/LenderCommitmentGroup_Smart.sol#L307

## Tools Used
Manual Review.

## Recommendation
Check balance before and after transferring, then update accounting.
