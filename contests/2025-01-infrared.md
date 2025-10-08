# Infrared Contracts

The [Infrared Protocol](https://cantina.xyz/code/ac5f64e6-3bf2-4269-bbb0-4bcd70425a1d/overview) revolutionizes the way users engage with the Berachain ecosystem, particularly in how they stake consensus assets and receive the Proof-of-Liquidity inflation.

## Audit Findings Summary

| ID | Title | Severity |
|----|----------|----------|
| [H-1](#h-1-attacker-can-permanently-lock-user-vault-rewards) | Attacker can permanently lock user vault rewards | High |
| [L-1](#l-1-infraredsetibgt-and-infraredsetred-should-have-access-control) | Infrared::setIBGT and Infrared::setRed should have access control | Low |
---

## [H-1] Attacker can permanently lock user vault rewards

## Summary

getRewardForUser of the MultiRewards contract is a permissionless function that anyone can execute to claim rewards on behalf of a user who has staked tokens in a vault.

However, there is an issue in the function that allows an attacker to intentionally cause the reward token-transfer to fail, by exploiting the 63/64 gas rule. The user's reward accounting is reset to 0, thus permanently lost.

## Finding Description

MultiRewards.sol#L225-L249
```javascript
function getRewardForUser(address _user)
        public
        nonReentrant
        updateReward(_user)
    {
        onReward();
        uint256 len = rewardTokens.length;
        for (uint256 i; i < len; i++) {
            address _rewardsToken = rewardTokens[i];
            uint256 reward = rewards[_user][_rewardsToken];
            if (reward > 0) {
                rewards[_user][_rewardsToken] = 0; //@audit reset rewards to 0
@>              (bool success, bytes memory data) = _rewardsToken.call( //@audit send user token
                    abi.encodeWithSelector(
                        ERC20.transfer.selector, _user, reward
                    )
                );
                if (success && (data.length == 0 || abi.decode(data, (bool)))) {
                    emit RewardPaid(_user, _rewardsToken, reward);
                } else {
@>                  continue; //@audit if token transfer failed, continue
                }
            }
        }
    }
```
An external call is made to send the user reward token, but if the call fails the function continues instead of reverting.

The 63/64 gas rule essentially means that only 63/64 of the gasleft() is forwarded to the external call. An attacker can send enough gas such that the low-level call "transfer" will fail, but the getRewardForUser function will successfully execute.

Since the failed transfer does not revert, and the user rewards mapping is reset to 0 rewards[_user][_rewardsToken] = 0;, user rewards are permanently lost.

Furthermore, the token recovery mechanism does not apply to reward tokens, so these tokens cannot be saved either.

## Impact Explanation

High - user rewards are permanently lost.

## Likelihood Explanation

High - function is completely permissionless, anyone can execute this attack with little to no cost.

## Recommendation

My recommendation is to re-implement this function to allow an additional parameter that allows the caller to specify the token which the user can receive rewards for, and to revert if the token transfer fails.

This way, if token transfer fails it will indeed revert, but it won't block any other retrieval of reward token.

Something like this:
```javascript
function getRewardForUser(address _user, address _rewardsToken)
        public
        nonReentrant
        updateReward(_user)
    {
        onReward();
        uint256 reward = rewards[_user][_rewardsToken];
        if (reward > 0) {
            rewards[_user][_rewardsToken] = 0;
            (bool success, bytes memory data) = _rewardsToken.call(
                abi.encodeWithSelector(
                    ERC20.transfer.selector, _user, reward
                )
            );
            if (success && (data.length == 0 || abi.decode(data, (bool)))) {
                emit RewardPaid(_user, _rewardsToken, reward);
            } else {
                revert();
            }
        }
    }
```
Or only allow users to collect their own tokens, like it's done in curvefi

## [L-1] Infrared::setIBGT and Infrared::setRed should have access control

## Finding Description

Looking at the setIBGT and setRed functions of the Infrared contract:

Infrared.sol#L402-L430
```javascript
/// @inheritdoc IInfrared
    function setIBGT(address _ibgt) external {
        if (_ibgt == address(0)) revert Errors.ZeroAddress();
        if (address(ibgt) != address(0)) revert Errors.AlreadySet(); //@audit if already set revert
        if (
            !InfraredBGT(_ibgt).hasRole(
                InfraredBGT(_ibgt).MINTER_ROLE(), address(this)
            )
        ) {
            revert Errors.Unauthorized(address(this));
        }
        ibgt = InfraredBGT(_ibgt);
        _vaultStorage().updateWhitelistedRewardTokens(address(ibgt), true);
        ibgtVault = IInfraredVault(_vaultStorage().registerVault(address(ibgt)));

        emit NewVault(msg.sender, address(ibgt), address(ibgtVault));
        emit IBGTSet(msg.sender, _ibgt);
    }

    /// @inheritdoc IInfrared
    function setRed(address _red) external {
        if (_red == address(0)) revert Errors.ZeroAddress();
        if (address(red) != address(0)) revert Errors.AlreadySet(); //@audit if already set, revert
        if (!IRED(_red).hasRole(IRED(_red).MINTER_ROLE(), address(this))) {
            revert Errors.Unauthorized(address(this));
        }
        red = IRED(_red);
        emit RedSet(msg.sender, _red);
    }
```
These functions set the ibgt, ibgtVault, red addresses.

ibgt: The InfraredBGT liquid staked token

ibgtVault: The InfraredBGT vault

red: The RED token (reward token)

The fact that anyone can set these addresses means that they can cause issues such as DoS to any use of RED token or anytime the ibgt/ibgtvault is interacted with, by simply deploying their own contract and reverting any interaction with these addresses.

## Impact Explanation

Medium - infrared contracts are unusable, but can simply be redeployed.

## Likelihood Explanation

Low - there's not much incentive for anyone to do this, other than to grief the protocol

## Recommendation

Consider adding onlyGovernor modifier on these functions
