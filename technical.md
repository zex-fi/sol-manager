# Zex Asset Manager – Technical Documentation

This document describes the **Zex Asset Manager** Solana program, its account structures, instructions, and security considerations.

---

## Table of Contents

1. [Overview](#overview)
2. [Program Constants](#program-constants)
3. [PDAs and Account Structures](#pdas-and-account-structures)
4. [Instruction Methods](#instruction-methods)
   - [Configuration Management](#configuration-management)
   - [Fund Management](#fund-management)
   - [Emergency Withdrawals](#emergency-withdrawals)
5. [Replay Protection and Signature Verification](#replay-protection-and-signature-verification)
6. [Access Control](#access-control)
7. [Rent Awareness](#rent-awareness)
8. [Potential Risks and Security Notes](#potential-risks-and-security-notes)

---

## Overview

The **Zex Asset Manager** is a Solana program to manage deposits and withdrawals of **SOL** and **SPL tokens**.  

- Users deposit funds into **user-specific PDAs** (`USER_VAULTS_SEED` + salt).  
- Funds are transferred into the **main vault PDA** (`MAIN_VAULTS_SEED`) for custody.  
- Withdrawals require **off-chain signature verification** using a trusted `frost_pubkey`.  
- Replay protection is implemented via **withdraw_id PDAs** (`WITHDRAW_ID_SEED`).  

---

## Program Constants

| Constant | Description |
|----------|-------------|
| `ASSETMAN_CONFIG_V1_SEEDS` | PDA seed for v1 config account |
| `ASSETMAN_CONFIG_SEEDS` | PDA seed for v2 config account |
| `MAIN_VAULTS_SEED` | PDA seed for the main vault |
| `USER_VAULTS_SEED` | PDA seed for per-user vaults |
| `WITHDRAW_ID_SEED` | PDA seed for tracking used withdraw IDs |
| `MAX_WITHDRAWER_LEN` | Maximum number of authorized withdrawers |

---

## PDAs and Account Structures

### Configs (v1 and v2)

- `ConfigsV1` (old version)
  - `admin`: Admin Pubkey
  - `withdrawers`: List of Pubkeys authorized to withdraw
  - `frost_pubkey`: Off-chain signer Pubkey

- `Configs` (v2)
  - `admin`
  - `withdrawers`
  - `frost_pubkey`
  - `paused`: Boolean flag to pause the program

**Security Notes:**  
- Admin-only methods enforce constraints based on `configs.admin`.  
- Withdrawer methods enforce constraints based on `configs.withdrawers`.  

### Vaults

- `user_vault` PDAs: Derived using `[USER_VAULTS_SEED, salt]`. Each user has their own PDA.  
- `main_vault` PDA: Derived using `[MAIN_VAULTS_SEED]`. Stores consolidated funds.  

### WithdrawIDRecord

- Tracks usage of withdraw IDs to prevent replay attacks.  
- Fields: `used: bool`  

### Token Accounts

- SPL tokens are managed via Anchor's **Associated Token Accounts** (`AssociatedToken`).  
- Each vault and destination account for SPL transfers is a token account tied to a specific mint.

---

## Instruction Methods

### Configuration Management

#### `initialize`
- Creates the main config PDA.
- Stores admin and `frost_pubkey`.
- Checks that `frost_pubkey` is not default.

#### `migrate_configs`
- Migrates old v1 configs to v2.
- Copies admin, withdrawers, frost_pubkey.
- Sets `paused` = false.

#### `set_pause`
- Pauses/unpauses program.
- Only callable by admin.
- Paused program disables withdrawals.

#### `transfer_admin`
- Changes admin Pubkey.
- Only callable by current admin.
- Cannot set default Pubkey.

#### `withdrawer_add`
- Adds a new withdrawer.
- Only admin.
- Checks duplicates and maximum length.

#### `withdrawer_delete`
- Removes a withdrawer.
- Only admin.

#### `set_frost_pubkey`
- Updates the off-chain signer Pubkey.
- Only admin.
- Checks that new `frost_pubkey` is not default.

---

### Fund Management

#### `transfer_sol_to_main_vault`
- Transfers all SOL from user vault PDA to main vault PDA.
- Anyone can call (open function).
- Uses PDA as authority via seeds `[USER_VAULTS_SEED, salt, bump]`.

#### `withdraw_sol`
- Withdraw SOL from main vault.
- Only authorized withdrawers.
- Requires **off-chain signature** verification (`frost_pubkey`) including `withdraw_id`.
- Checks `withdraw_id_record` to prevent replay.
- Rent-exempt aware transfer.

#### `transfer_spl_to_main_vault`
- Transfers all SPL tokens from user's token account to main vault token account.
- Anyone can call.
- Uses PDA authority with seeds `[USER_VAULTS_SEED, salt, bump]`.

#### `withdraw_spl`
- Withdraw SPL tokens from main vault to destination.
- Only authorized withdrawers.
- Off-chain signature verification with `withdraw_id`.
- Checks sufficient balance in main vault token account.

---

### Emergency Withdrawals

#### `emergency_withdraw_sol`
- Admin-only SOL withdrawal from main vault.
- Rent-exempt aware transfer.
- Emits `EmergencyWithdraw` event.

#### `emergency_withdraw_spl`
- Admin-only SPL withdrawal.
- Emits `EmergencyWithdraw` event.

---

## Replay Protection and Signature Verification

- Uses `WithdrawIDRecord` PDAs to mark each withdraw ID as used.
- Off-chain signature verification ensures only authorized withdrawals are processed.
- Messages include `withdraw_id` to prevent replay.

---

## Access Control

| Action | Authorized Role |
|--------|----------------|
| Pause/unpause program | Admin |
| Add/remove withdrawers | Admin |
| Update frost_pubkey | Admin |
| Emergency withdrawals | Admin |
| Withdraw SOL/SPL | Registered withdrawer |
| Transfer user vault to main vault | Anyone |

**Note:** Transfer from user vault → main vault is **intentionally open**, as the main vault consolidates funds.

---

## Rent Awareness

- SOL withdrawals subtract the rent-exempt minimum from the main vault balance.
- Ensures the main vault remains rent-exempt and cannot be drained entirely.

---

## Potential Risks and Security Notes

1. **Open user vault transfer:**  
   - Anyone can call `transfer_sol_to_main_vault` or `transfer_spl_to_main_vault`.
   - Funds always go to main vault PDA (program-controlled), so safe.

2. **Signature verification:**  
   - Withdrawals require a valid off-chain `frost_pubkey` signature.
   - Includes `withdraw_id` for replay protection.

3. **Replay protection:**  
   - Each withdraw ID has a dedicated PDA (`WITHDRAW_ID_SEED + withdraw_id`).
   - Prevents double spending of the same withdrawal request.

4. **SPL mint checks:**  
   - `InvalidMint` error prevents empty or invalid token accounts.

5. **PDAs:**  
   - `MAIN_VAULTS_SEED` and `USER_VAULTS_SEED` use seeds + bump for program authority.
   - Only program can sign via PDA seeds.

6. **Paused state:**  
   - When paused, withdrawals are disabled.
   - Only admin can pause/unpause.

---

## Summary

- **Deposits:** Users deposit into user-specific PDAs → anyone moves funds to main vault.  
- **Withdrawals:** Require off-chain signature, replay protection, and authorized withdrawer.  
- **Emergency Withdrawals:** Admin-only, ensures liquidity control in emergencies.  
- **Security:** PDAs, rent-exempt awareness, signature verification, replay protection, access controls.  
