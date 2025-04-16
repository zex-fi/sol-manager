import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { ZexAssetManager } from "../target/types/zex_asset_manager"; // Import the generated types for your program

describe("zex-asset-manager", () => {
  // Configure the provider to use the local cluster.
  const provider = anchor.AnchorProvider.env(); // Use environment-based provider
  anchor.setProvider(provider); // Set the provider for the program

  // Get the program object. This will be linked to your deployed program.
  const program = anchor.workspace.zexAssetManager as Program<ZexAssetManager>;

  // Define the accounts
  let admin: anchor.web3.Keypair;
  let vault: anchor.web3.Keypair;

  // Before each test, generate new keypairs for accounts
  beforeEach(async () => {
    admin = anchor.web3.Keypair.generate();
    vault = anchor.web3.Keypair.generate();
  });

  it("Is initialized!", async () => {
    // Create a transaction to initialize the program
    const tx = await program.methods
        .initialize(admin.publicKey) // Assuming `initialize()` is a method in your contract
        .accounts({
          admin: admin.publicKey, // Set the admin account here
        })
        .signers([admin]) // Sign the transaction with the admin account
        .rpc(); // Send the transaction

    console.log("Your transaction signature", tx); // Log the signature for verification
  });

  // Test for transferring SOL to the vault
  it("Transfers SOL to vault", async () => {
    const amount = new anchor.BN(1000000000); // 1 SOL (in lamports)

    // Fetch the initial balance of the vault
    const initialVaultBalance = await provider.connection.getBalance(vault.publicKey);

    // Execute the transfer method
    const tx = await program.methods
        .transferSolToMainVault(amount) // Assuming `transferSolToMainVault` is the method
        .accounts({
          admin: admin.publicKey,
          vault: vault.publicKey,
        })
        .signers([admin]) // Admin signs the transaction
        .rpc();

    console.log("Transaction signature for transfer:", tx);

    // Fetch the final balance of the vault
    const finalVaultBalance = await provider.connection.getBalance(vault.publicKey);

    // Check if the final balance increased by the amount transferred
    expect(finalVaultBalance).toEqual(initialVaultBalance + amount.toNumber());
  });
});
