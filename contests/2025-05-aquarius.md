# Aquarius

This is the [AMM protocol](https://cantina.xyz/code/990ce947-05da-443e-b397-be38a65f0bff/overview) built on Stellar smart contract platform (Soroban) that allows spinning up 2 types of pools: volatile (inspired by Uniswap V2) and stable (inspired by Curve), as well as swapping assets in these pools including multihop routes where assetA is swapped into assetC with 2 swaps A=>B and B=>C in case A/C pool does not exist.

## Audit Findings Summary

| ID | Title | Severity |
|----|----------|----------|
| [M-1](#m-1-pool-reward-configuration-can-be-exploited-to-inflate-reward-distribution) | Pool reward configuration can be exploited to inflate reward distribution | Medium |
| [L-1](#l-1-dangerous-use-of-instance-storage-vs-persistent-storage-for-unbounded-data) | Dangerous use of instance storage vs persistent storage for unbounded data | Low |
| [L-2](#l-2-actual-maximum-pools-for-a-standard-pool-is-vastly-less-than-the-max_pools_for_pair-configured) | Actual maximum pools for a standard pool is vastly less than the MAX_POOLS_FOR_PAIR configured | Low |
| [L-3](#l-3-incorrect-validation-in-get_deposit_amounts) | Incorrect validation in get_deposit_amounts | Low |
| [I-1](#i-1-swap_strict_receive-can-revert-if-in_max--in_amount-for-some-tokens) | swap_strict_receive can revert if in_max == in_amount for some tokens | Informational |
| [I-2](#i-2-min_a-min_b-slippage-always-hardcoded-to-0-in-standard-pools) | min_a, min_b slippage always hardcoded to 0 in standard pools | Informational |
| [I-3](#i-3-mi-05-transfer_from-usage-from-previous-audit-is-not-completely-resolved) | MI-05 transfer_from Usage from previous audit is not completely resolved | Informational |
| [I-4](#i-4-first-lp-can-create-maximum-stable-pools-for-token-pair-with-max-fee-for-profit) | First LP can create maximum stable pools for token pair with max fee for profit | Informational |
---

## [M-1] Pool reward configuration can be exploited to inflate reward distribution

## Description

Looking at the pool router contract, the following two functions can be called permissionlessly after pool creation:

https://cantina.xyz/code/990ce947-05da-443e-b397-be38a65f0bff/liquidity_pool_router/src/contract.rs?lines=782,782
```javascript
// Fills the aggregated liquidity information for a given set of tokens.
    //
    // # Arguments
    //
    // * `tokens` - A vector of token addresses for which to fill the liquidity.
    fn fill_liquidity(e: Env, tokens: Vec<Address>) {
        assert_tokens_sorted(&e, &tokens);
        let tokens_salt = get_tokens_salt(&e, &tokens);
        let calculator = get_liquidity_calculator(&e);
@>      let (pools, total_liquidity) = get_total_liquidity(&e, &tokens, calculator); //@audit note pool liquidity fetched here

        let mut pools_with_processed_info = Map::new(&e);
        for (key, value) in pools {
            pools_with_processed_info.set(key, (value, false));
        }

        let mut tokens_with_liquidity = get_reward_tokens(&e);
        let mut token_data = match tokens_with_liquidity.get(tokens.clone()) {
            Some(v) => v,
            None => panic_with_error!(e, LiquidityPoolRouterError::TokensAreNotForReward),
        };
        if token_data.processed {
            panic_with_error!(e, LiquidityPoolRouterError::LiquidityAlreadyFilled);
        }
        token_data.processed = true;
        token_data.total_liquidity = total_liquidity;
        tokens_with_liquidity.set(tokens, token_data);
        set_reward_tokens(&e, &tokens_with_liquidity);
        set_reward_tokens_detailed(&e, tokens_salt, &pools_with_processed_info);
    }

    // Configures the rewards for a specific pool.
    //
    // This function is used to set up the rewards configuration for a specific pool.
    // It calculates the pool's share of the total rewards based on its liquidity and sets the pool's rewards configuration.
    //
    // # Arguments
    //
    // * `tokens` - A vector of token addresses that the pool consists of.
    // * `pool_index` - The index of the pool.
    //
    // # Returns
    //
    // * `pool_tps` - The total reward tokens per second (TPS) to be distributed to the pool.
    //
    // # Errors
    //
    // This function will panic if:
    //
    // * The pool does not exist.
    // * The tokens are not found in the current rewards configuration.
    // * The liquidity for the tokens has not been filled.
    fn config_pool_rewards(e: Env, tokens: Vec<Address>, pool_index: BytesN<32>) -> u128 {
        assert_tokens_sorted(&e, &tokens);
        let pool_id = get_pool(&e, &tokens, pool_index.clone());

        let rewards_config = get_rewards_config(&e);
        let tokens_salt = get_tokens_salt(&e, &tokens);
        let mut tokens_detailed = get_reward_tokens_detailed(&e, tokens_salt.clone());
        let tokens_reward = get_reward_tokens(&e);
        let tokens_reward_info = tokens_reward.get(tokens.clone());

        let (pool_liquidity, pool_configured) = if tokens_reward_info.is_some() {
            tokens_detailed
                .get(pool_index.clone())
                .unwrap_or((U256::from_u32(&e, 0), false))
        } else {
            (U256::from_u32(&e, 0), false)
        };

        if pool_configured {
            panic_with_error!(&e, LiquidityPoolRouterError::RewardsAlreadyConfigured);
        }

        let reward_info = match tokens_reward_info {
            Some(v) => v,
            // if tokens not found in current config, deactivate them
            None => LiquidityPoolRewardInfo {
                voting_share: 0,
                processed: true,
                total_liquidity: U256::from_u32(&e, 0),
            },
        };

        if !reward_info.processed {
            panic_with_error!(&e, LiquidityPoolRouterError::LiquidityNotFilled);
        }
        // it's safe to convert tps to u128 since it cannot be bigger than total tps which is u128
        let pool_tps = if pool_liquidity > U256::from_u32(&e, 0) {
            U256::from_u128(&e, rewards_config.tps)
                .mul(&U256::from_u32(&e, reward_info.voting_share))
@>              .mul(&pool_liquidity) //@audit note pool liquidity used here
                .div(&reward_info.total_liquidity)
                .div(&U256::from_u32(&e, 1_0000000))
                .to_u128()
                .unwrap()
        } else {
            0
        };

        e.invoke_contract::<Val>(
            &pool_id,
            &Symbol::new(&e, "set_rewards_config"),
            Vec::from_array(
                &e,
                [
                    e.current_contract_address().to_val(),
                    rewards_config.expired_at.into_val(&e),
                    pool_tps.into_val(&e),
                ],
            ),
        );

        if pool_tps > 0 {
            // mark pool as configured to avoid reentrancy
            tokens_detailed.set(pool_index, (pool_liquidity, true));
            set_reward_tokens_detailed(&e, tokens_salt, &tokens_detailed);
        }

        Events::new(&e).config_rewards(tokens, pool_id, pool_tps, rewards_config.expired_at);

        pool_tps
    }
```

fill_liquidity takes a snapshot of the pool liquidity and sets reward tokens, where then config_pool_rewards can be called to configure the pool_tps, which determines reward calculation. fill_liquidity can only be called once per token set, whereas config_pool_rewards can only be called once per pool.

An attacker can take advantage of this by inflating with the total liquidity of the pool by sandwiching their own fill_liquidity call with a massive deposit (i.e flash loan if possible), followed by an immediate withdrawal. The total_liquidity now snapshotted is heavily inflated.

Thus the config_pool_rewards will heavily inflate reward distribution for LPs for that pool.

The impact is as follows:

1. If other pools of this token pair exists, then LPs are heavily incentivized to only use this pool to maximize rewards. This is a loss for LPs of other pools and unfair to them as they will earn much less rewards, also to the creators of these other pools who had to pay fees to even initialize that pool, just for another pool to earn far more rewards.

2. If somehow this attack was conducted after LPs had already deposited, then the rewards accumulated during that time the LPs had their deposit will be significantly lower than how much the attacker and LPs will now earn when keeping their tokens locked for a much shorter period. This will be unfair to earlier LPs.

3. This will also have a negative impact on the value of the reward token, since more rewards are distributed without actual liquidity contribution, undermining the reward token’s value.

## Recommendation

Perhaps use a TWAP for this functionality and/or add a timelock between deposits and withdrawal

## [L-1] Dangerous use of instance storage vs persistent storage for unbounded data

## Description

Here is a blog post describing how dangerous it is to use instance storage for unbounded data in Soroban contracts.

There are 3 types of storage:

Temporary: For storing data for a short amount of time

Persistent: Data that keeps incrementing without limit

Instance: "For small data directly associated with the current contract, such as its admin, configuration settings, tokens the contract operates on etc." (quoted from blog).

To paraphrase from the blog:

Soroban docs state that Instance Storage should not be used with any data that can scale in unbounded fashion as it is loaded completely every time the contract is invoked, using unbounded data will cause the invocations to become more and more expensive over time until a DoS state is reached.

Overall, the protocol handled it quite well, but there are two cases that can be dangerous:

https://cantina.xyz/code/990ce947-05da-443e-b397-be38a65f0bff/liquidity_pool_router/src/storage.rs?lines=116,116
```javascript
generate_instance_storage_getter_and_setter_with_default!(
    pool_counter,
    DataKey::PoolCounter,
    u128,
    0
);
generate_instance_storage_getter_and_setter_with_default!(
    tokens_set_count,
    DataKey::TokensSetCounter,
    u128,
    0
);
```
These counter values can pose dangers as it does increase without a limit.

For example, any time a pool is created, the counter is incremented and set in instance storage:

https://cantina.xyz/code/990ce947-05da-443e-b397-be38a65f0bff/liquidity_pool_router/src/storage.rs?lines=290,290
```javascript
pub fn get_pool_next_counter(e: &Env) -> u128 {
    let value = get_pool_counter(e);
    set_pool_counter(e, &(value + 1));
    value
}
```
https://cantina.xyz/code/990ce947-05da-443e-b397-be38a65f0bff/liquidity_pool_router/src/pool_utils.rs?lines=28,28
```javascript
pub fn get_stableswap_pool_salt(e: &Env) -> BytesN<32> {
    let mut salt = Bytes::new(e);
    salt.append(&symbol_short!("stable").to_xdr(e));
    salt.append(&symbol_short!("0x00").to_xdr(e));
    // no constant pool parameters, though hash should be different, so we add pool counter
@>  salt.append(&get_pool_next_counter(e).to_xdr(e));
    salt.append(&symbol_short!("0x00").to_xdr(e));
    e.crypto().sha256(&salt).to_bytes()
}

pub fn get_pool_counter_salt(e: &Env) -> BytesN<32> {
    let mut salt = Bytes::new(e);
    salt.append(&symbol_short!("0x00").to_xdr(e));
@>  salt.append(&get_pool_next_counter(e).to_xdr(e));
    salt.append(&symbol_short!("0x00").to_xdr(e));
    e.crypto().sha256(&salt).to_bytes()
}
```

## Recommendation

Use persistent storage in this case, because the data is unbounded. Although it shouldn't take up 64KB instance storage limit causing DoS, it still has impact and is violating Soroban best practices.

## [L-2] Actual maximum pools for a standard pool is vastly less than the MAX_POOLS_FOR_PAIR configured

## Description

The maximum standard pools allowed for a pair is set to 10:

https://cantina.xyz/code/990ce947-05da-443e-b397-be38a65f0bff/liquidity_pool_router/src/constants.rs?lines=1,1
```javascript
pub(crate) const MAX_POOLS_FOR_PAIR: u32 = 10;
```
https://cantina.xyz/code/990ce947-05da-443e-b397-be38a65f0bff/liquidity_pool_router/src/storage.rs?lines=265,265
```javascript
if pools.len() > MAX_POOLS_FOR_PAIR {
        panic_with_error!(&e, LiquidityPoolRouterError::PoolsOverMax);
    }
```
However, for a new pool to be created for a pair, it must have a unique fee amount. For example if a pair tokenA, tokenB exist with fee = 1%, the create pool function will simply return instead of creating a new pool:
```javascript
fn init_standard_pool(
        e: Env,
        user: Address,
        tokens: Vec<Address>,
        fee_fraction: u32,
    ) -> (BytesN<32>, Address) {
        user.require_auth();
        validate_tokens_contracts(&e, &tokens);
        assert_tokens_sorted(&e, &tokens);

        if !CONSTANT_PRODUCT_FEE_AVAILABLE.contains(&fee_fraction) {
            panic_with_error!(&e, LiquidityPoolRouterError::BadFee);
        }

        let salt = get_tokens_salt(&e, &tokens);
        let pools = get_pools_plain(&e, salt);
@>      let pool_index = get_standard_pool_salt(&e, &fee_fraction);

        match pools.get(pool_index.clone()) {
@>          Some(pool_address) => (pool_index, pool_address),
            None => {
                // pay for pool creation
                let init_pool_token = get_init_pool_payment_token(&e);
                let init_pool_amount = get_init_standard_pool_payment_amount(&e);
                let init_pool_address = get_init_pool_payment_address(&e);
                if init_pool_amount > 0 {
                    SorobanTokenClient::new(&e, &init_pool_token).transfer(
                        &user,
                        &init_pool_address,
                        &(init_pool_amount as i128),
                    );
                }

                deploy_standard_pool(&e, &tokens, fee_fraction)
            }
        }
    }
```
The pool_index must be unique to create a new pool, thus the fee_fraction must be unique. However, these pools only have 3 possible fee fractions:

https://cantina.xyz/code/990ce947-05da-443e-b397-be38a65f0bff/liquidity_pool_router/src/constants.rs?lines=2,2

pub(crate) const CONSTANT_PRODUCT_FEE_AVAILABLE: [u32; 3] = [10, 30, 100];
If the fee is not configured to one of these values, pool creation for that pair will revert:

https://cantina.xyz/code/990ce947-05da-443e-b397-be38a65f0bff/liquidity_pool_router/src/contract.rs?lines=1156,1156
```javascript
if !CONSTANT_PRODUCT_FEE_AVAILABLE.contains(&fee_fraction) {
            panic_with_error!(&e, LiquidityPoolRouterError::BadFee);
        }
```
Therefore only 3 different pools can exist for a token pair each configured to fee_fraction 10,30,100 respectively.

This is 7 pools less than the maximum that the protocol has intended to set, which justified low severity as it is a disruption to the protocol and the amount of pools a token pair can actually have will now be very limited.

## Recommendation

If the intention is to really have 10 pools as the maximum, allow for duplicate pools with the same fee fraction, otherwise just set the max to 3 to avoid confusion

## [L-3] Incorrect validation in get_deposit_amounts

## Description

Standard pools execute the following when depositing:

https://cantina.xyz/code/990ce947-05da-443e-b397-be38a65f0bff/liquidity_pool/src/pool.rs?lines=7,7
```javascript
pub fn get_deposit_amounts(
    e: &Env,
    desired_a: u128,
    min_a: u128,
    desired_b: u128,
    min_b: u128,
    reserve_a: u128,
    reserve_b: u128,
) -> (u128, u128) {
    if reserve_a == 0 && reserve_b == 0 {
        return (desired_a, desired_b);
    }

    let amount_b = desired_a.fixed_mul_floor(e, &reserve_b, &reserve_a);
    if amount_b <= desired_b {
        if amount_b < min_b {
            panic_with_error!(e, LiquidityPoolValidationError::InvalidDepositAmount);
        }
        (desired_a, amount_b)
    } else {
        let amount_a = desired_b.fixed_mul_floor(&e, &reserve_a, &reserve_b);
@>      if amount_a > desired_a || desired_a < min_a {
            panic_with_error!(e, LiquidityPoolValidationError::InvalidDepositAmount);
        }
        (amount_a, desired_b)
    }
}
```
We can see the check desired_a < min_a is incorrect as it checks user's desired amount against the minimum amount when it should be the actual amount_a amount checked against this, as it's done in the first branch.

Currently, this poses no issue as min_a, min_b are set to 0 in the deposit contract, however this can be problematic if any changes occur with how min_a,min_b is used and the slippage check, which should be if amount_a < min_a, can be bypassed.

## Recommendation

Simply change desired_a < min_a to amount_a < min_a

## [I-1] swap_strict_receive can revert if in_max == in_amount for some tokens

## Description

swap_strict_receive has the following transfer executed, even if in_max == in_amount (meaning 0 transfer):

https://cantina.xyz/code/990ce947-05da-443e-b397-be38a65f0bff/liquidity_pool/src/contract.rs?lines=574,574
```javascript
// Return the difference
        sell_token_client.transfer(
            &e.current_contract_address(),
            &user,
            &((in_max - in_amount) as i128),
        );
```
It's possible some tokens will be used that can revert on 0 transfer, including custom tokens. I currently don't have examples for Stellar/Soroban, but tokens like these do exist on the EVM ecosystem, as you can check here. Therefore it's possible some already exist that will be used in this protocol or will in the future.

## Recommendation

Check if in_max > in_amount before performing the transfer.

## [I-2] min_a, min_b slippage always hardcoded to 0 in standard pools

Standard pool deposit function allows users to specify min_shares slippage, which is sufficient because the current implementation enforces that the amounts paid by user cannot exceed desired amounts specified.

However, there is also min_a, min_b (a, b tokens) in the deposit implementation

https://cantina.xyz/code/990ce947-05da-443e-b397-be38a65f0bff/liquidity_pool/src/contract.rs?lines=275,275
```javascript
let (min_a, min_b) = (0, 0);

        // Calculate deposit amounts
        let amounts =
            pool::get_deposit_amounts(&e, desired_a, min_a, desired_b, min_b, reserve_a, reserve_b);
```

This code is redundant as this slippage is not utilized, and the current slippage is sufficient, however it is important the team is aware of this hardcoded 0 slippage for min_a and min_b output as it can be extremely dangerous if any changes/upgrades are made that rely on these values.

## Recommendation

Remove the code or document this

## [I-3] MI-05 transfer_from Usage from previous audit is not completely resolved

## Description

In the previous audit by CoinFabrik, the following was stated under issue MI-05:
```text
In soroban, it is a bad practice to use transfer_from to transfer tokens when using
transfer can work, as the allowance mechanism is prone to errors such as leaving a
pre-approved allowance either by error or to ease the use of the contract. This exposes the
user to potential issues in the contract.
```

Followed by the mitigation and status:
```text
Recommendation
Use transfer instead of transfer_from to transfer funds. To better integrate with
soroban's authorization framework, transfer all the funds and then transfer back all the
unused funds if necessary.

Status
Resolved. All transfer_from calls were replaced by transfer calls. Checked on commit
de33577d289c008862a5b8b0bc561e6802c21ecc.
```

However, not all transfer_from calls were actually replaced by transfer calls as stated by the team, looking at the router contract:

https://cantina.xyz/code/990ce947-05da-443e-b397-be38a65f0bff/liquidity_pool_router/src/contract.rs?lines=1077,1077
```javascript
if from != e.current_contract_address() {
            SorobanTokenClient::new(&e, &reward_token).transfer_from(
                &e.current_contract_address(),
                &from,
                &pool_id,
                &(outstanding_reward as i128),
            );
```

From my perspective, I believe the team had forgot to remove this transfer_from because it's clearly stated that all transfer_from were replaced by transfer calls. Even if it's intentional, I believe reporting as informational is best

## Recommendation

Document this or consider removing transfer_from

## [I-4] First LP can create maximum stable pools for token pair with max fee for profit

## Summary

Stable pools have a maximum of 3 pools for each token pair, but it uses a different pool index salt for the same, already existing, token pair with the same fees. This means that all 3 stable pools for the same pair and same fee can be created.

This is different from standard pools, which include the fee in the salt, therefore a standard pool token pair with the same fee cannot be created again if it already exists (as intended).

A malicious actor can simply create 3 stable pools for a token pair, for example USDC + DAI pair, with the maximum fee of 1%. Since the max number of pools for creating a stable pool with the same token pair is 3, any other pool creations with USDC + DAI pair will DoS.

Therefore, the actor can become the first LP for all existing USDC + DAI pair pools and have a guarantee to maximize profits by ensuring the fee is maximum for each pair. This can be repeated for any popular token pair for stable pools.

This would force all users to operate under maximum fees for each of the existing stable pools, causing a loss for them, while the first LP profits heavily.

## Finding Description

init_stableswap_pool
```javascript
fn init_stableswap_pool(
        e: Env,
        user: Address,
        tokens: Vec<Address>,
        fee_fraction: u32,
    ) -> (BytesN<32>, Address) {
        user.require_auth();
        validate_tokens_contracts(&e, &tokens);
        assert_tokens_sorted(&e, &tokens);

        if fee_fraction > STABLESWAP_MAX_FEE {
            panic_with_error!(&e, LiquidityPoolRouterError::BadFee);
        }

        let salt = get_tokens_salt(&e, &tokens);
        let pools = get_pools_plain(&e, salt);
@>      let pool_index = get_stableswap_pool_salt(&e); //@audit new index each time

        match pools.get(pool_index.clone()) {
            Some(pool_address) => (pool_index, pool_address),
@>          None => { //@audit this will always be executed, even if pool with same token and fee already exists
                // pay for pool creation
                let init_pool_token = get_init_pool_payment_token(&e);
                let init_pool_amount = get_init_stable_pool_payment_amount(&e);
                let init_pool_address = get_init_pool_payment_address(&e);
                if init_pool_amount > 0 {
                    SorobanTokenClient::new(&e, &init_pool_token).transfer(
                        &user,
                        &init_pool_address,
                        &(init_pool_amount as i128),
                    );
                }

                // calculate amplification factor
                // Amp = A*N**(N-1)
                let n = tokens.len();
                let amp = STABLESWAP_DEFAULT_A * (n as u128).pow(n - 1);
                deploy_stableswap_pool(&e, &tokens, amp, fee_fraction)
            }
        }
    }
```
pool_index will always be new because of how get_stableswap_pool_salt uses a counter:

get_stableswap_pool_salt
```javascript
pub fn get_stableswap_pool_salt(e: &Env) -> BytesN<32> {
    let mut salt = Bytes::new(e);
    salt.append(&symbol_short!("stable").to_xdr(e));
    salt.append(&symbol_short!("0x00").to_xdr(e));
    // no constant pool parameters, though hash should be different, so we add pool counter
@>  salt.append(&get_pool_next_counter(e).to_xdr(e));
    salt.append(&symbol_short!("0x00").to_xdr(e));
    e.crypto().sha256(&salt).to_bytes()
}
```
Since a counter is used, each time this function is called a new salt will return. This is different from standard pools, which use the fee_fraction for the salt, ensuring that only one pool pair of that same fee can exist. (i.e if USDC/BTC pair of 1% fee exist already for standard pool, then the init pool function will do nothing).

Also note that only 3 stable pools of the same token pair can exist:

constants.rs
```javascript
pub(crate) const STABLESWAP_MAX_POOLS: u32 = 3;
add_pool

pub fn add_pool(
    e: &Env,
    salt: BytesN<32>,
    pool_index: BytesN<32>,
    pool_type: LiquidityPoolType,
    pool_address: Address,
) {
    let mut pools = get_pools(e, salt.clone());
    pools.set(
        pool_index,
        LiquidityPoolData {
            pool_type,
            address: pool_address,
        },
    );

    if pool_type == LiquidityPoolType::StableSwap {
        let mut stableswap_pools_amt = 0;
        for (_key, value) in pools.iter() {
            if value.pool_type == LiquidityPoolType::StableSwap {
                stableswap_pools_amt += 1;
            }
        }
@>      if stableswap_pools_amt > STABLESWAP_MAX_POOLS { //@audit if 3 pools already revert
            panic_with_error!(&e, LiquidityPoolRouterError::StableswapPoolsOverMax);
        }
    }

    if pools.len() > MAX_POOLS_FOR_PAIR {
        panic_with_error!(&e, LiquidityPoolRouterError::PoolsOverMax);
    }
    put_pools(e, salt, &pools);
}
```
Therefore a malicious actor can create 3 stable pools of the same token pair with max fee percentage and be the first LP provider of all of 3 of these pools. This is a guarantee for the LP to gain maximum profits, especially if popular tokens are used, and will be disruptive to users who have no choice but to be taxed maximally for all possible pools of that token pair.

This will also be a loss for the protocol as it will incentivize other users to use pools from other protocols that do not enforce maximum fees for popular used tokens.

## Proof of Concept

PoC proving that the same token pair and fee used for stable pool will return different index salts, making the scenario above possible:
```javascript
use std::collections::HashMap;
use std::cell::RefCell;

// Mock the essential functions to demonstrate the vulnerability
struct MockEnv {
    pool_counter: RefCell<u128>,
}

impl MockEnv {
    fn new() -> Self {
        Self {
            pool_counter: RefCell::new(0),
        }
    }
    
    fn get_pool_next_counter(&self) -> u128 {
        let mut counter = self.pool_counter.borrow_mut();
        let value = *counter;
        *counter += 1;
        value
    }
}

// Simulate the get_stableswap_pool_salt function behavior
fn get_stableswap_pool_salt(env: &MockEnv) -> String {
    let counter = env.get_pool_next_counter();
    format!("stable_0x00_{}_0x00", counter)
}

// Simulate get_tokens_salt - this is deterministic based on tokens
fn get_tokens_salt(tokens: &[&str]) -> String {
    let mut combined = String::new();
    for token in tokens {
        combined.push_str(token);
    }
    format!("tokens_{}", combined)
}

fn main() {
    println!("=== Testing Duplicate Stableswap Pool Creation Bug ===\n");
    
    let env = MockEnv::new();
    
    // Same tokens and fee for all attempts
    let tokens = vec!["tokenA", "tokenB"];
    let fee_fraction = 30u32; // 0.3%
    
    println!("Testing with:");
    println!("- Tokens: {:?}", tokens);
    println!("- Fee: {}%", fee_fraction as f64 / 100.0);
    println!();
    
    // Simulate the pool creation logic
    let tokens_salt = get_tokens_salt(&tokens);
    let mut pools: HashMap<String, String> = HashMap::new();
    
    println!("1. tokens_salt = get_tokens_salt(&tokens) = {}", tokens_salt);
    println!("2. pools = get_pools_plain(&env, tokens_salt) = empty initially\n");
    
    // First pool creation
    println!("=== FIRST POOL CREATION ===");
    let pool_index_1 = get_stableswap_pool_salt(&env);
    println!("pool_index = get_stableswap_pool_salt(&env) = {}", pool_index_1);
    
    match pools.get(&pool_index_1) {
        Some(existing_pool) => {
            println!("Pool exists, returning: {}", existing_pool);
        }
        None => {
            println!("Pool doesn't exist, creating new pool");
            pools.insert(pool_index_1.clone(), "pool_address_1".to_string());
            println!("Created pool: {}", pool_index_1);
        }
    }
    
    // Second pool creation with SAME parameters
    println!("\n=== SECOND POOL CREATION (SAME TOKENS, SAME FEE) ===");
    let pool_index_2 = get_stableswap_pool_salt(&env);
    println!("pool_index = get_stableswap_pool_salt(&env) = {}", pool_index_2);
    
    match pools.get(&pool_index_2) {
        Some(existing_pool) => {
            println!("Pool exists, returning: {}", existing_pool);
        }
        None => {
            println!("Pool doesn't exist, creating ANOTHER new pool!");
            pools.insert(pool_index_2.clone(), "pool_address_2".to_string());
            println!("Created DUPLICATE pool: {}", pool_index_2);
        }
    }
    
    // Third pool creation
    println!("\n=== THIRD POOL CREATION (SAME TOKENS, SAME FEE) ===");
    let pool_index_3 = get_stableswap_pool_salt(&env);
    println!("pool_index = get_stableswap_pool_salt(&env) = {}", pool_index_3);
    
    match pools.get(&pool_index_3) {
        Some(existing_pool) => {
            println!("Pool exists, returning: {}", existing_pool);
        }
        None => {
            println!("Pool doesn't exist, creating YET ANOTHER new pool!");
            pools.insert(pool_index_3.clone(), "pool_address_3".to_string());
            println!("Created ANOTHER DUPLICATE pool: {}", pool_index_3);
        }
    }
    
    // Show final state
    println!("\n=== FINAL POOLS STATE ===");
    println!("Total pools created: {}", pools.len());
    for (index, address) in &pools {
        println!("  {} -> {}", index, address);
    }
    
    

}
```
Run the command rustc test_duplicate_pools.rs -o test_duplicate && ./test_duplicate

Output:
```text
=== Testing Duplicate Stableswap Pool Creation Bug ===

Testing with:
- Tokens: ["tokenA", "tokenB"]
- Fee: 0.3%

1. tokens_salt = get_tokens_salt(&tokens) = tokens_tokenAtokenB
2. pools = get_pools_plain(&env, tokens_salt) = empty initially

=== FIRST POOL CREATION ===
pool_index = get_stableswap_pool_salt(&env) = stable_0x00_0_0x00
Pool doesn't exist, creating new pool
Created pool: stable_0x00_0_0x00

=== SECOND POOL CREATION (SAME TOKENS, SAME FEE) ===
pool_index = get_stableswap_pool_salt(&env) = stable_0x00_1_0x00
Pool doesn't exist, creating ANOTHER new pool!
Created DUPLICATE pool: stable_0x00_1_0x00

=== THIRD POOL CREATION (SAME TOKENS, SAME FEE) ===
pool_index = get_stableswap_pool_salt(&env) = stable_0x00_2_0x00
Pool doesn't exist, creating YET ANOTHER new pool!
Created ANOTHER DUPLICATE pool: stable_0x00_2_0x00

=== FINAL POOLS STATE ===
Total pools created: 3
  stable_0x00_1_0x00 -> pool_address_2
  stable_0x00_0_0x00 -> pool_address_1
  stable_0x00_2_0x00 -> pool_address_3
```

## Recommendation

Similar to creating standard pools, include the fees within the salt for stable pool indexing, and have a specific list of fee percentages that can be chosen since the limit of number of pools for that token list is only 3.
