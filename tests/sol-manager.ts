import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { ZexAssetManager } from "../target/types/zex_asset_manager";
import assert from "assert";
import { Keypair, PublicKey, SendTransactionError, SystemProgram, TransactionInstruction } from "@solana/web3.js";
import * as fs from "fs";
import bs58 from "bs58";
import * as crypto from "crypto";


const ASSETMAN_CONFIG_SEEDS = Buffer.from("assetman-configs"); // Updated seed
const MAIN_VAULTS_SEED = Buffer.from("main-vault");
const USER_VAULTS_SEED = Buffer.from("user-vault");


describe("zex-asset-manager", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const program = anchor.workspace.zexAssetManager as Program<ZexAssetManager>;
    console.log("JS Program ID:", program.programId.toBase58());


    let admin: anchor.web3.Keypair = anchor.web3.Keypair.generate();
    fs.writeFileSync("admin.json", JSON.stringify(Array.from(admin.secretKey)));

    // const secret = JSON.parse(fs.readFileSync("admin.json", "utf-8"));
    // let admin = anchor.web3.Keypair.fromSecretKey(Uint8Array.from(secret));

    console.log(admin.publicKey)

    let configs_publicKey: PublicKey;
    let vault_publicKey: PublicKey;
    let bump: number;

    [configs_publicKey, bump] = anchor.web3.PublicKey.findProgramAddressSync(
        [ASSETMAN_CONFIG_SEEDS],
        program.programId
    );
    [vault_publicKey, bump] = anchor.web3.PublicKey.findProgramAddressSync(
        [MAIN_VAULTS_SEED],
        program.programId
    );

    beforeEach(async () => {
        const sig = await provider.connection.requestAirdrop(
            admin.publicKey,
            5 * anchor.web3.LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig);
    });

    console.log("Initializing");
    it("Is initialized!", async () => {
        const tx = await program.methods
            .initialize(admin.publicKey)
            .accounts({
                admin: admin.publicKey,
            })
            .signers([admin])
            .rpc();

        console.log("Initialization transaction signature:", tx);
    });

    it("Adds an admin", async () => {
      const newAdmin = anchor.web3.Keypair.generate();

      // Add new admin to the system
      const tx = await program.methods
          .adminAdd(newAdmin.publicKey)
          .accounts({
              admin: admin.publicKey,
              configs: configs_publicKey, // Initialize configs account
          })
          .signers([admin])
          .rpc();

      console.log("Add admin transaction signature:", tx);

      // Fetch the list of admins and check if newAdmin was added
      const admins = await program.account.configs.fetch(configs_publicKey);
      // BAz9UESAfLiyNHNgy5u6gXEPRykgLrnYoaPf4zU3tjM2
      console.log("Admin list:", admins.admins);
      console.log("newAdmin:", newAdmin.publicKey);
        assert.ok(admins.admins.map((k) => k.toBase58()).includes(newAdmin.publicKey.toBase58()),  "New admin was not added");
    });

    it("Removes an admin", async () => {
      const newAdmin = anchor.web3.Keypair.generate();

      // Add new admin first
      await program.methods
          .adminAdd(newAdmin.publicKey)
          .accounts({
              admin: admin.publicKey,
              configs: configs_publicKey, // Initialize configs account
          })
          .signers([admin])
          .rpc();

      // Remove admin
      const tx = await program.methods
          .adminDelete(newAdmin.publicKey)
          .accounts({
              admin: admin.publicKey,
              configs: configs_publicKey,
          })
          .signers([admin])
          .rpc();

      console.log("Remove admin transaction signature:", tx);

      // Fetch the list of admins and verify that newAdmin was removed
      const admins = await program.account.configs.fetch(configs_publicKey);
        assert.ok(!admins.admins.map((k) => k.toBase58()).includes(newAdmin.publicKey.toBase58()), "Admin was not removed");

    });

    it("Sets withdraw authority", async () => {
      const newWithdrawAuthority = anchor.web3.Keypair.generate().publicKey;

      const tx = await program.methods
          .setWithdrawAuthority(newWithdrawAuthority)
          .accounts({
            admin: admin.publicKey,
          })
          .signers([admin])
          .rpc();

      console.log("Set withdraw authority transaction signature:", tx);

      // Fetch the new withdraw authority and verify it's updated
      const config = await program.account.configs.fetch(configs_publicKey);
      assert.strictEqual(config.withdrawAuthor.toString(), newWithdrawAuthority.toString(), "Withdraw authority was not updated");
    });

    it("Transfers SOL to vault", async () => {
        console.log("program id", program.programId); //FdHzkmeyEosHXxrTvuaeCBvv5Ne97BnHGn3rCmTB9ZXQ
        let user_public_key : PublicKey;

        const user_salt = new anchor.BN(5);
        const salt_bytes = user_salt.toBuffer("le", 8);

        [user_public_key, ] = anchor.web3.PublicKey.findProgramAddressSync(
            [USER_VAULTS_SEED, salt_bytes],
            program.programId
        );
        console.log("Program ID:", program.programId.toBase58());
        console.log("USER_VAULTS_SEED:", USER_VAULTS_SEED);
        console.log("Salt bytes (LE):", salt_bytes);
        console.log("Salt bytes hex:", salt_bytes.toString("hex"));
        console.log("user_vault PDA:", user_public_key.toBase58());
        console.log("Bump seed:", bump);

        console.log("user public_key", user_public_key);

        const lamports = 2 * anchor.web3.LAMPORTS_PER_SOL;

        const sig = await provider.connection.requestAirdrop(
            user_public_key,
            lamports
        );
        await provider.connection.confirmTransaction(sig);

        const initialVaultBalance = await provider.connection.getBalance(vault_publicKey);
        const initialUserBalance = await provider.connection.getBalance(user_public_key);

        console.log("vault public_key:", vault_publicKey);
        console.log("initialVaultBalance:", initialVaultBalance.toString());
        console.log("initialUserBalance:", initialUserBalance.toString());

        const txSig = await program.methods
            .transferSolToMainVault(user_salt)
            .accounts({
                user_public_key,
                vault_publicKey,
                systemProgram: anchor.web3.SystemProgram.programId,
            })
            .rpc();

        console.log("Transfer SOL transaction signature:", txSig);

        const finalVaultBalance = await provider.connection.getBalance(vault_publicKey);
        console.log("finalVaultBalance:", finalVaultBalance.toString());

        const finalUserBalance = await provider.connection.getBalance(user_public_key);
        console.log("finalUserBalance:", finalUserBalance.toString());

        assert.strictEqual(
          finalVaultBalance,
          initialVaultBalance + lamports,
          "Vault balance should increase by transferred amount"
        );
    });

    it("Withdraw From Vault", async () => {
        const destination = anchor.web3.Keypair.generate().publicKey;
        const withdrawId = new anchor.BN(2);
        const withdrawIdByte = withdrawId.toArrayLike(Buffer, "le", 8);
        const amount = new anchor.BN(1000000);

        let withdrawIdRecordPDA: PublicKey;

        [withdrawIdRecordPDA] = PublicKey.findProgramAddressSync(
            [
                Buffer.from("withdraw_id"),
                destination.toBuffer(),
                withdrawIdByte,
            ],
            program.programId
        );

        // Create the WithdrawIDRecord account (rent exempt)
        const sig1 = await provider.connection.requestAirdrop(
            destination,
            5 * anchor.web3.LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig1);

        // Build message as defined in your program
        const base58Dest = bs58.encode(destination.toBytes());
        const message = Buffer.from(
            `allowed withdraw ${amount.toString()} SOL to address ${base58Dest} with withdraw_id ${withdrawId.toString()}`
        );

        // Sign message using Solana Keypair
        const privateKeyRaw = admin.secretKey.slice(0, 32); // Only first 32 bytes needed
        const keyObject = crypto.createPrivateKey({
            key: Buffer.concat([
                Buffer.from([
                    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
                    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
                ]),
                privateKeyRaw,
            ]),
            format: "der",
            type: "pkcs8",
        });
        const signature = crypto.sign(null, message, keyObject);

        // Create Ed25519 instruction
        const ed25519Ix = new TransactionInstruction({
            programId: new PublicKey("Ed25519SigVerify111111111111111111111111111"),
            keys: [],
            data: (() => {
                const publicKey = admin.publicKey.toBytes();

                const data = Buffer.alloc(
                    1 + // signature count
                    1 + // padding
                    32 + // public key
                    1 + // padding
                    2 + // sig length
                    64 + // sig
                    2 + // msg length
                    message.length // msg
                );

                let offset = 0;
                data[offset++] = 1; // sig count
                data[offset++] = 0; // padding
                Buffer.from(publicKey).copy(data, offset);
                offset += 32;
                data[offset++] = 0; // padding
                data.writeUInt16LE(64, offset);
                offset += 2;
                Buffer.from(signature).copy(data, offset);
                offset += 64;
                data.writeUInt16LE(message.length, offset);
                offset += 2;
                Buffer.from(message).copy(data, offset);

                return data;
            })(),
        });

        // Build program instruction
        const programIx = await program.methods
            .withdrawSol(amount, withdrawId, Array.from(signature))
            .accounts({
                configs: configs_publicKey,
                main_vault: vault_publicKey,
                destination: destination,
                instructions: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
                withdraw_id_record: withdrawIdRecordPDA,
                system_program: SystemProgram.programId,
            })
            .instruction();
        const tx = new anchor.web3.Transaction();
        tx.add(ed25519Ix);
        tx.add(programIx);

        try {
            const sig = await provider.sendAndConfirm(tx);
            console.log("✅ Transaction Signature:", sig);
        } catch (e) {
            console.log(await e.getLogs())
            console.log('//////')
            const logs = e.logs ?? (await (e as any).simulationResponse.value.logs);
            console.error("Transaction failed logs:\n", logs.join("\n"));
            throw e;
        }
    });
});
