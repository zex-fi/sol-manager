import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { ZexAssetManager } from "../target/types/zex_asset_manager";
import assert from "assert";
import { PublicKey } from "@solana/web3.js";
import * as fs from "fs";


const ASSETMAN_CONFIG_SEEDS = Buffer.from("assetman-configs"); // Updated seed
const MAIN_VAULTS_SEED = Buffer.from("main-vault");
const USER_VAULTS_SEED = Buffer.from("user-vault");


describe("zex-asset-manager", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.zexAssetManager as Program<ZexAssetManager>;
    console.log("JS Program ID:", program.programId.toBase58());


    // let admin: anchor.web3.Keypair = anchor.web3.Keypair.generate();
  // fs.writeFileSync("admin.json", JSON.stringify(Array.from(admin.secretKey)));

  const secret = JSON.parse(fs.readFileSync("admin.json", "utf-8"));
  let admin = anchor.web3.Keypair.fromSecretKey(Uint8Array.from(secret));

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
        1 * anchor.web3.LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(sig);
  });

  console.log("Initializing");
  it("Is initialized!", async () => {
    const tx = await program.methods
        .initialize(admin.publicKey)
        .accounts({
          admin: admin.publicKey,
          // vault: vault.publicKey,
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

      const user_salt = 1;
      const salt_bytes = new anchor.BN(user_salt).toBuffer("be", 8);

      [user_public_key, ] = anchor.web3.PublicKey.findProgramAddressSync(
          [USER_VAULTS_SEED, salt_bytes],
          anchor.web3.SystemProgram.programId
      );
      console.log("Program ID:", program.programId.toBase58());
      console.log("USER_VAULTS_SEED:", "user-vault");
      console.log("Salt bytes (LE):", salt_bytes);
      console.log("Salt bytes hex:", salt_bytes.toString("hex"));
      console.log("user_vault PDA:", user_public_key.toBase58());
      console.log("Bump seed:", bump);

      console.log("user public_key", user_public_key);
      const sig = await provider.connection.requestAirdrop(
          user_public_key,
          2 * anchor.web3.LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(sig);

      const amount = new anchor.BN(1 * anchor.web3.LAMPORTS_PER_SOL);

      const initialVaultBalance = await provider.connection.getBalance(vault_publicKey);

      console.log("vault public_key:", vault_publicKey);
      console.log("initialVaultBalance:", initialVaultBalance.toString());

      const userVaultInfo = await provider.connection.getAccountInfo(user_public_key);
      console.log("userVaultInfo:", userVaultInfo);

      const tx = await program.methods
        .transferSolToMainVault(new anchor.BN(user_salt))
        .accounts({
            user_vault: user_public_key,
            main_vault: vault_publicKey,
            system_program: anchor.web3.SystemProgram.programId,
        })
        // .signers([admin])
        .rpc();
      console.log("Transfer SOL transaction signature:", tx);

      const finalVaultBalance = await provider.connection.getBalance(vault_publicKey);
      assert.strictEqual(
        finalVaultBalance,
        initialVaultBalance + amount.toNumber(),
        "Vault balance should increase by transferred amount"
      );
  });
  
});
