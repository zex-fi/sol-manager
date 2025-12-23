import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { ZexAssetManager } from "../target/types/zex_asset_manager";
import assert from "assert";
import { Ed25519Program, Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import bs58 from "bs58";
import {
    createMint,
    getAssociatedTokenAddressSync,
    getOrCreateAssociatedTokenAccount,
    mintTo,
    TOKEN_PROGRAM_ID,
    transfer
} from '@solana/spl-token';
import { ASSOCIATED_PROGRAM_ID } from '@coral-xyz/anchor/dist/cjs/utils/token';
import { createHash } from 'crypto';
import { expect } from "chai";
import { keyGen, signFrost } from "./frost-utils";


const ASSETMAN_CONFIG_SEEDS = Buffer.from("assetman-configs"); // Updated seed
const MAIN_VAULTS_SEED = Buffer.from("main-vault");
const USER_VAULTS_SEED = Buffer.from("user-vault");
const WITHDRAW_ID_SEED = Buffer.from("withdraw-id");

// Helper functions for salt encoding (matching Rust implementation)
function encodeSalt(salt: number): Buffer {
    const length = salt === 0 ? 1 : Math.floor((salt.toString(2).length + 7) / 8);
    const bytes = Buffer.alloc(length);

    // Convert to big-endian bytes
    for (let i = length - 1; i >= 0; i--) {
        bytes[i] = (salt >> ((length - 1 - i) * 8)) & 0xFF;
    }

    return bytes;
}

function computeTweakBy(salt: number): Buffer {
    const encodedSalt = encodeSalt(salt);
    const hash = createHash('sha3-256');
    hash.update(Buffer.from('P'));
    hash.update(encodedSalt);
    return hash.digest();
}



describe("zex-asset-manager", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const program = anchor.workspace.zexAssetManager as Program<ZexAssetManager>;
    console.log("JS Program ID:", program.programId.toBase58());

    // create frost threshold key
    const { keyPackages, pubkeyPackage } = keyGen(3, 2);
    const frostPubkey: PublicKey = new PublicKey(Buffer.from(pubkeyPackage["verifying_key"], "hex"));

    let oldAdmin: anchor.web3.Keypair = anchor.web3.Keypair.generate();
    let admin: anchor.web3.Keypair = anchor.web3.Keypair.generate();
    // fs.writeFileSync("admin.json", JSON.stringify(Array.from(newAdmin.secretKey)));

    const withdrawers = [0, 1, 2, 3, 4].map(_ => anchor.web3.Keypair.generate())

    // const secret = JSON.parse(fs.readFileSync("admin.json", "utf-8"));
    // let admin = anchor.web3.Keypair.fromSecretKey(Uint8Array.from(secret));
    // console.log("admin", admin.publicKey.toBase58());

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


    const DECIMALS = 2;
    async function createTokenMint(authority: PublicKey): Promise<PublicKey> {
        const mint = await createMint(
            provider.connection,
            // @ts-ignore
            admin,
            authority,
            null,
            DECIMALS // Decimal places for the token
        );
        return mint;
    }

    async function mintTokens(mint: PublicKey, owner: PublicKey, amount: number) {
        const destination = await getOrCreateAssociatedTokenAccount(
            provider.connection,
            // @ts-ignore
            admin,
            mint,
            owner,
        )

        return await mintTo(
            provider.connection,
            // @ts-ignore
            admin,
            mint,
            destination.address,
            // @ts-ignore
            admin,
            amount
        );
    }
    // Function to create an associated token account
    async function createAssociatedTokenAccount(mint: PublicKey, owner: PublicKey, allowOwnerOffCurve?: boolean): Promise<PublicKey> {
        const account = await getOrCreateAssociatedTokenAccount(
            provider.connection,
            // @ts-ignore
            admin,
            mint,
            owner,
            allowOwnerOffCurve,
        );
        return account.address;
    }

    async function transferToken(mint: PublicKey, from: PublicKey, to: PublicKey, amount: number) {
        const fromTokenAccount = getAssociatedTokenAddressSync(mint, from, true)
        const toTokenAccount = await createAssociatedTokenAccount(mint, to, true)
        return await transfer(
            provider.connection,
            admin,
            fromTokenAccount,
            toTokenAccount,
            from,
            amount
        )
    }

    async function request_airdrop_to_admin() {
        const sig = await provider.connection.requestAirdrop(
            admin.publicKey,
            5 * anchor.web3.LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig);

        const sig2 = await provider.connection.requestAirdrop(
            oldAdmin.publicKey,
            5 * anchor.web3.LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig2);
    }

    async function withdrawSol(amount: any, destination: PublicKey, withdrawId: any, signer: Keypair) {
        amount = new anchor.BN(amount);
        withdrawId = new anchor.BN(withdrawId);

        const withdrawIdByte = withdrawId.toArrayLike(Buffer, "le", 8);
        const [withdrawIdRecordPDA,] = PublicKey.findProgramAddressSync(
            [WITHDRAW_ID_SEED, withdrawIdByte,],
            program.programId
        );

        // Build message as defined in your program
        const base58Dest = bs58.encode(destination.toBytes());
        const message = Buffer.from(
            `allowed withdraw ${amount.toString()} SOL to address ${base58Dest} with withdraw_id ${withdrawId.toString()}`
        );

        const signatureStr = signFrost(message, keyPackages, pubkeyPackage);
        const signature = Buffer.from(signatureStr, "hex");

        // Create Ed25519 instruction

        const ed25519Ix = Ed25519Program.createInstructionWithPublicKey({
            signature: signature,
            message: message,
            publicKey: frostPubkey.toBytes()
        })

        // Build program instruction
        // console.log("withdrawIdRecordPDA:", withdrawIdRecordPDA)
        // console.log("main vault", vault_publicKey);
        // console.log("destination", destination);
        const programIx = await program.methods
            // @ts-ignore
            .withdrawSol(amount, withdrawId, signature)
            .accounts({
                signer: signer.publicKey,
                configs: configs_publicKey,
                mainVault: vault_publicKey,
                destination: destination,
                instructions: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
                withdrawIdRecord: withdrawIdRecordPDA,
                systemProgram: SystemProgram.programId,
            })
            .instruction();
        const tx = new anchor.web3.Transaction();
        tx.add(ed25519Ix);
        tx.add(programIx);

        await provider.sendAndConfirm(tx, [signer]);
    }

    async function withdrawSpl(amount: any, destination: PublicKey, withdrawId: any, signer: Keypair) {
        amount = new anchor.BN(amount);
        withdrawId = new anchor.BN(withdrawId);
        const withdrawIdByte = withdrawId.toArrayLike(Buffer, "le", 8);

        await transferToken(mint, admin.publicKey, vault_publicKey, amount);

        const [withdrawIdRecordPDA,] = PublicKey.findProgramAddressSync(
            [WITHDRAW_ID_SEED, withdrawIdByte],
            program.programId
        );

        const destination_token_account = getAssociatedTokenAddressSync(mint, destination, true);
        const main_vault_token_account = getAssociatedTokenAddressSync(mint, vault_publicKey, true);


        // Build message as defined in your program
        const base58Dest = bs58.encode(destination.toBytes());
        const message = Buffer.from(
            `allowed withdraw ${amount.toString()} ${mint.toString()} to address ${base58Dest} with withdraw_id ${withdrawId.toString()}`
        );

        const signatureStr = signFrost(message, keyPackages, pubkeyPackage);
        const signature = Buffer.from(signatureStr, "hex");

        // Create Ed25519 instruction
        const ed25519Ix = Ed25519Program.createInstructionWithPublicKey({
            signature: signature,
            message: message,
            publicKey: frostPubkey.toBytes()
        })

        const programIx = await program.methods
            // @ts-ignore
            .withdrawSpl(amount, withdrawId, signature)
            .accounts({
                signer: signer.publicKey,
                configs: configs_publicKey,
                main_vault: vault_publicKey,
                mainVaultTokenAccount: main_vault_token_account,
                destination: destination,
                destinationTokenAccount: destination_token_account,
                mint: mint,
                instructions: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
                tokenProgram: TOKEN_PROGRAM_ID,
                associatedTokenProgram: ASSOCIATED_PROGRAM_ID,
                withdraw_id_record: withdrawIdRecordPDA,
            })
            .instruction();

        const tx = new anchor.web3.Transaction();
        tx.add(ed25519Ix);
        tx.add(programIx);

        const sig = await provider.sendAndConfirm(tx, [signer]);
    }

    let mint: PublicKey;

    before(async () => {
        await request_airdrop_to_admin();

        mint = await createTokenMint(admin.publicKey);

        const mintAmount = 10_000;
        await mintTokens(mint, admin.publicKey, mintAmount);
    })

    beforeEach(async () => {
        await request_airdrop_to_admin();
    });

    it("Is initialized!", async () => {
        const tx = await program.methods
            .initialize(oldAdmin.publicKey)
            .accounts({
                admin: oldAdmin.publicKey,
            })
            .signers([oldAdmin])
            .rpc();

        const configAccount = await program.account.configs.fetch(configs_publicKey);
        expect(configAccount.admin.toBase58()).to.equal(oldAdmin.publicKey.toBase58());
    });

    it("Can transfer admin", async () => {
        await program.methods
            .transferAdmin(admin.publicKey)
            .accounts({
                admin: oldAdmin.publicKey,
                configs: configs_publicKey, // Initialize configs account
            })
            .signers([oldAdmin])
            .rpc();

        // Fetch the list of admins and check if newAdmin was added
        const admins = await program.account.configs.fetch(configs_publicKey);
        assert.ok(admins.admin.equals(admin.publicKey), "New admin was not added");
    });

    it("Sets frost PublicKey", async () => {
        const newWithdrawAuthority = anchor.web3.Keypair.generate().publicKey;

        const tx = await program.methods
            .setFrostPubkey(frostPubkey)
            .accounts({
                admin: admin.publicKey,
            })
            .signers([admin])
            .rpc();

        // Fetch the new withdraw authority and verify it's updated
        const config = await program.account.configs.fetch(configs_publicKey);
        assert.strictEqual(config.frostPubkey.toString(), frostPubkey.toString(), "Withdraw authority was not updated");
    });

    it("Old admin cannot add a new withdrawer", async () => {
        try {
            await program.methods
                .withdrawerAdd(withdrawers[0].publicKey)
                .accounts({
                    admin: oldAdmin.publicKey,
                    configs: configs_publicKey,
                })
                .signers([oldAdmin])
                .rpc()
            expect.fail("Transaction should have failed");
        } catch (err: any) {
            expect(err.message).to.match(/Admin restricted method/i);
        }
    });

    it("Admin can add a withdrawer", async () => {
        // Add new admin to the system
        const tx = await program.methods
            .withdrawerAdd(withdrawers[0].publicKey)
            .accounts({
                admin: admin.publicKey,
                configs: configs_publicKey, // Initialize configs account
            })
            .signers([admin])
            .rpc();

        // Fetch the list of admins and check if newAdmin was added
        const configs = await program.account.configs.fetch(configs_publicKey);
        assert.ok(configs.withdrawers.map((k) => k.toBase58()).includes(withdrawers[0].publicKey.toBase58()), "Withdrawer was not added");
    });

    it("Admin can remove a withdrawer", async () => {
        await program.methods
            .withdrawerAdd(withdrawers[1].publicKey)
            .accounts({
                admin: admin.publicKey,
                configs: configs_publicKey,
            })
            .signers([admin])
            .rpc();


        const configs1 = await program.account.configs.fetch(configs_publicKey);
        assert.ok(configs1.withdrawers.map((k) => k.toBase58()).includes(withdrawers[1].publicKey.toBase58()), "Withdrawer is not added");

        const tx = await program.methods
            .withdrawerDelete(withdrawers[1].publicKey)
            .accounts({
                admin: admin.publicKey,
                configs: configs_publicKey,
            })
            .signers([admin])
            .rpc();


        const configs2 = await program.account.configs.fetch(configs_publicKey);
        assert.ok(!configs2.withdrawers.map((k) => k.toBase58()).includes(withdrawers[1].publicKey.toBase58()), "Withdrwer is not removed");
    });

    it("Transfers SOL to vault", async () => {
        let user_vault: PublicKey;
        const salt_bytes = computeTweakBy(1);

        [user_vault, bump] = anchor.web3.PublicKey.findProgramAddressSync(
            [USER_VAULTS_SEED, salt_bytes],
            program.programId
        );

        const lamports = 2 * anchor.web3.LAMPORTS_PER_SOL;

        const sig = await provider.connection.requestAirdrop(
            user_vault,
            lamports
        );
        await provider.connection.confirmTransaction(sig);

        const initialVaultBalance = await provider.connection.getBalance(vault_publicKey);

        const txSig = await program.methods
            // @ts-ignore
            .transferSolToMainVault(salt_bytes)
            .accounts({
                userVault: user_vault,
                mainVault: vault_publicKey,
            })
            .rpc();

        const finalVaultBalance = await provider.connection.getBalance(vault_publicKey);

        assert.strictEqual(
            finalVaultBalance,
            initialVaultBalance + lamports,
            "Vault balance should increase by transferred amount"
        );
    });

    it("Transfers SPL to vault", async () => {
        let user_vault: PublicKey;

        const salt_bytes = computeTweakBy(5);

        [user_vault,] = anchor.web3.PublicKey.findProgramAddressSync(
            [USER_VAULTS_SEED, salt_bytes],
            program.programId
        );

        const user_token_account = getAssociatedTokenAddressSync(mint, user_vault, true);;
        const main_vault_token_account = getAssociatedTokenAddressSync(mint, vault_publicKey, true);;

        // console.log("User vault PDA:", user_vault.toBase58());
        // console.log("Vault publicKey:", vault_publicKey.toBase58());
        // console.log("User token account:", user_token_account.toBase58());
        // console.log("Main vault token account:", main_vault_token_account.toBase58());

        const token_amount = 1000;
        await transferToken(mint, admin.publicKey, user_vault, token_amount);

        const txSig = await program.methods
            // @ts-ignore
            .transferSplToMainVault(salt_bytes)
            .accounts({
                userVault: user_vault,
                mainVault: vault_publicKey,
                userTokenAccount: user_token_account,
                mainVaultTokenAccount: main_vault_token_account,
                mint: mint,
                tokenProgram: TOKEN_PROGRAM_ID,
                associatedTokenProgram: ASSOCIATED_PROGRAM_ID
            })
            .rpc();

        // console.log("Tx Signature:", txSig);

        const main_vault_token_balance = await provider.connection.getTokenAccountBalance(main_vault_token_account);
        // console.log("Main vault token balance after:", main_vault_token_balance.value.amount);


        assert.strictEqual(
            token_amount.toString(),
            main_vault_token_balance.value.amount,
            "Vault balance should increase by transferred amount"
        );
    });

    it("No one can withdraw SOL from main vault except withdrawers", async () => {
        const destination = anchor.web3.Keypair.generate().publicKey;
        const withdrawId = 1;
        const amount = 100_000_000;

        const sig2 = await provider.connection.requestAirdrop(
            vault_publicKey,
            10 * anchor.web3.LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig2);

        const sig3 = await provider.connection.requestAirdrop(
            withdrawers[1].publicKey,
            10 * anchor.web3.LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig3);

        try {
            await withdrawSol(amount, destination, withdrawId, withdrawers[1]);
            expect.fail("Transaction should have failed");
        } catch (err: any) {
            expect(err.message).to.match(/Unauthorized withdrawer/i);
        }
    });

    it("Withdraw SOL From Vault", async () => {
        const destination = anchor.web3.Keypair.generate().publicKey;
        const withdrawId = 1;
        const amount = 100_000_000;

        const sig2 = await provider.connection.requestAirdrop(
            vault_publicKey,
            10 * anchor.web3.LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig2);
        const initialVaultBalance = await provider.connection.getBalance(destination);

        const sig3 = await provider.connection.requestAirdrop(
            withdrawers[0].publicKey,
            10 * anchor.web3.LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig3);

        await withdrawSol(amount, destination, withdrawId, withdrawers[0])

        const finalVaultBalance = await provider.connection.getBalance(destination);

        assert.strictEqual(
            finalVaultBalance,
            initialVaultBalance + amount,
            "Vault balance should increase by transferred amount"
        );
    });

    it("No one can withdraw SPL from main vault except withdrawers", async () => {
        const destination = anchor.web3.Keypair.generate().publicKey;

        const amount = 1000;
        const withdrawId = 2;

        try {
            await withdrawSpl(amount, destination, withdrawId, admin)
            expect.fail("Transaction should have failed");
        } catch (err: any) {
            expect(err.message).to.match(/Unauthorized withdrawer/i);
        }
    });

    it("Withdraw SPL From Vault", async () => {
        const destination = anchor.web3.Keypair.generate().publicKey;

        const amount = 1000;
        const withdrawId = 2;

        await withdrawSpl(amount, destination, withdrawId, withdrawers[0])

        const destination_token_account = getAssociatedTokenAddressSync(mint, destination, true);
        const finalVaultBalance = await provider.connection.getTokenAccountBalance(destination_token_account);

        assert.strictEqual(
            amount.toString(),
            finalVaultBalance.value.amount,
            "Vault balance should increase by transferred amount"
        );
    });
});
