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