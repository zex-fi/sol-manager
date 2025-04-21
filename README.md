
# 🪙 ZEX Asset Manager

ZEX Asset Manager is a **Solana smart contract** written with **Anchor** that provides a secure and extensible vault management system for **custody, deposit, and withdrawal** of **SOL** and **SPL tokens**.

This contract is designed for **non-custodial DEXs, centralized exchanges (CEXs)** seeking on-chain transparency, or **decentralized apps** requiring verifiable and controlled fund flows, especially in scenarios that involve **off-chain withdrawal authorization via Ed25519 signatures**.

---

## ✨ Features

### ✅ Vault Architecture
- **User Vaults (PDA-based):** For temporary custody of user assets before transfer.
- **Main Vaults (PDA-based):** Central vault for holding all assets (SOL/SPL) securely.

### ✅ Administrative Control
- On-chain **multi-admin** support with add/remove functionality.
- Admin can update the **withdrawal authority** used for verifying off-chain signatures.

### ✅ Deposits
- Users can:
    - Deposit **SOL** into a user-specific vault, which is later moved to the main vault.
    - Deposit **SPL tokens** into a user-specific token vault, then moved to the main vault.

### ✅ Withdrawals (SOL & SPL)
- Withdrawals are authorized **off-chain** by a trusted **Ed25519 signer**.
- Withdrawal requests include:
    - `amount`
    - `withdraw_id` (replay protection)
    - `recipient`
    - `signature`
- On-chain validation ensures:
    - Signature matches expected message.
    - `withdraw_id` has not been used before.
    - Sufficient funds are available in vaults.

### ✅ Security
- Uses **Ed25519 instruction validation** to verify off-chain signatures.
- Prevents **replay attacks** using `withdraw_id` records stored on-chain.
- Handles **rent-exemption checks** when transferring SOL.

### 🛠 Dev Utilities (for testing only)
- Manual `withdraw_id` reset methods exist for test environments (to be removed before mainnet deployment).

---

## 🧱 Technical Stack

- **Language:** Rust
- **Framework:** Anchor
- **Chain:** Solana
- **Token Support:** Native SOL, SPL Tokens
- **Signature Format:** Ed25519 (used via `ed25519_program` syscall validation)
- **Program ID:** `FdHzkmeyEosHXxrTvuaeCBvv5Ne97BnHGn3rCmTB9ZXQ`

---

## 🔐 Security Assumptions

- Off-chain withdrawal signatures are securely generated and stored.
- Admin keys are managed with appropriate access control and key rotation procedures.
- Rent-awareness is ensured on SOL transfers to prevent draining of accounts.

---

## 🚀 Getting Started

```sh
anchor build
anchor deploy
```

To interact with the program:
- Use `anchor test` or your favorite Solana SDK (e.g. `@solana/web3.js` or `solana-py`) to invoke instructions.

---

## 🧪 Development Notes

- Make sure to **replace Ed25519 mock verifier** with production-grade logic or system instructions before mainnet launch.
- Remove `reset_withdraw_id` handlers before production deployment.
- Adjust vault seeds if integrating with multisig or DAO-controlled vaults.



---

Let me know if you want a detailed usage example section (with CLI or code snippets), diagrams for architecture, or a security section for audit docs.

## 📦 Build

Make sure you have Anchor installed (`anchor --version`) and are targeting the correct Solana cluster.

```bash
ANCHOR_LOG=true anchor idl build
```

## 🚀 Deploy

```bash
anchor deploy
```

## 🦀 Suggested Rust Version
```
rustc 1.86.0 
```

## ✅ To publish your IDL
```bash
anchor publish
```
The Anchor Program Registry is a decentralized registry where you can publish your program's IDL (Interface Description Language) to make it discoverable by others.

[registry]
url = "https://api.apr.dev"


## Reset localnet
```
solana-test-validator --reset
```