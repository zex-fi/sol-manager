mod ed25519;

use anchor_lang::{prelude::*, system_program};
use anchor_lang::system_program::{transfer, Transfer};
use anchor_lang::solana_program::sysvar::rent::Rent;
use anchor_spl::associated_token::{self, AssociatedToken};
use anchor_spl::token::{self, Mint, Token, TokenAccount};
use solana_program::sysvar::instructions::{
    load_current_index_checked,
    load_instruction_at_checked
};
use std::collections::HashSet;
use bs58;

const MIN_DEPOSIT_LAMPARDS: u64 = 1_000_000;
const ASSETMAN_CONFIG_SEEDS: &[u8] = b"assetman-configs";
const MAIN_VAULTS_SEED: &[u8] = b"main-vault";
const USER_VAULTS_SEED: &[u8] = b"user-vault";

declare_id!("Gr4CykSFMDyVPj8nwtfsftd8fp3YkWqRniCv5GKvqWRv");

fn get_withdraw_message(token: &str, public_key: &Pubkey, amount: u64) -> Vec<u8> {
    let base58_address = bs58::encode(public_key.to_bytes()).into_string();
    let formatted_string = format!("allowed withdraw {} {} to address {}", amount, token, base58_address);
    let byte_array: &[u8] = formatted_string.as_bytes();
    byte_array.to_vec()
}

#[program]
pub mod zex_assetman_sol {

    use super::*;

    // Initialize the Configs
    pub fn initialize(ctx: Context<Initialize>, withdraw_author: Pubkey) -> Result<()> {
        let admin = ctx.accounts.admin.key();
        let admins = vec![admin];

        let configs = &mut ctx.accounts.configs;
        configs.admins = admins;
        configs.withdraw_author = withdraw_author;

        Ok(())
    }

    // Add a new admin to the Configs
    #[access_control(ctx.accounts.configs.is_admin(&ctx.accounts.admin))]
    pub fn admin_add(ctx: Context<AdminAdd>, new_admin: Pubkey) -> Result<()> {
        let configs = &mut ctx.accounts.configs;

        let existing_admins: HashSet<Pubkey> = configs.admins.iter().cloned().collect();
        require!(!existing_admins.contains(&new_admin), CustomError::DuplicateError);

        configs.admins.push(new_admin);
        Ok(())
    }

    #[access_control(ctx.accounts.configs.is_admin(&ctx.accounts.admin))]
    pub fn admin_delete(ctx: Context<AdminDelete>, admin_to_remove: Pubkey) -> Result<()> {
        let configs = &mut ctx.accounts.configs;

        // Check if the admin to be removed is in the list
        let admin_index = configs.admins.iter().position(|&admin| admin == admin_to_remove);

        require!(admin_index.is_some(), CustomError::MissingData);
        require!(configs.admins.len() > 1, CustomError::EmptyAdmin);

        // Remove the admin
        configs.admins.remove(admin_index.unwrap());

        Ok(())
    }

    // Initialize the Configs
    #[access_control(ctx.accounts.configs.is_admin(&ctx.accounts.admin))]
    pub fn set_withdraw_authority(ctx: Context<SetWithdrawAuthority>, withdraw_author: Pubkey) -> Result<()> {
        let configs = &mut ctx.accounts.configs;
        configs.withdraw_author = withdraw_author;

        Ok(())
    }

    // TODO: Does it need to restrict the call to allowed accounts?
    pub fn transfer_sol_to_main_vault(
        ctx: Context<TransferSolToMainVault>,
        // agent id
        agent: [u8; 32],
        // agent's account index
        account: u64,
        // account's user index
        user: u64
    ) -> Result<()> {
        let vault = &ctx.accounts.user_vault;

        // Calculate the total SOL available in the PDA account
        let vault_lamports = **vault.lamports.borrow();
        // Ensure PDA has enough funds to transfer
        require!(vault_lamports > MIN_DEPOSIT_LAMPARDS, CustomError::InsufficientFunds);

        let bump_seed = ctx.bumps.user_vault;
        let signer_seeds: &[&[&[u8]]] = &[&[
            USER_VAULTS_SEED,
            &agent,
            &account.to_be_bytes(),
            &user.to_be_bytes(),
            &[bump_seed]
        ]];

        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            Transfer {
                from: ctx.accounts.user_vault.to_account_info(),
                to: ctx.accounts.main_vault.to_account_info(),
            },
        )
            .with_signer(signer_seeds);

        // Send the transfer instruction
        transfer(cpi_context, vault_lamports)?;

        Ok(())
    }

    pub fn withdraw_sol(
        ctx: Context<WithdrawSol>,
        amount: u64,
        signature: [u8; 64]
    ) -> Result<()> {
        let assetman = &ctx.accounts.configs;

        let index = load_current_index_checked(&ctx.accounts.instructions.to_account_info())?;
        require!(index >= 1, CustomError::VerifyFirst);

        let message = get_withdraw_message("SOL", &ctx.accounts.destination.key(), amount);

        let ix = load_instruction_at_checked(index as usize - 1, &ctx.accounts.instructions.to_account_info())?;
        ed25519::verify(&ix, &signature, &message, &assetman.withdraw_author.to_bytes())?;

        let vault = &ctx.accounts.main_vault;

        // Calculate the total SOL available in the PDA account
        let vault_lamports = **vault.lamports.borrow();
        let rent_exempt_minimum = Rent::get()?.minimum_balance(vault.data_len());
        let transferable_lamports = vault_lamports.saturating_sub(rent_exempt_minimum);

        // Ensure PDA has enough funds to transfer
        require!(amount <= transferable_lamports, CustomError::InsufficientFunds);

        let bump_seed = ctx.bumps.main_vault;
        let signer_seeds: &[&[&[u8]]] = &[&[MAIN_VAULTS_SEED, &[bump_seed]]];

        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            Transfer {
                from: ctx.accounts.main_vault.to_account_info(),
                to: ctx.accounts.destination.to_account_info(),
            },
        )
            .with_signer(signer_seeds);

        // Send the transfer instruction
        transfer(cpi_context, amount)?;

        Ok(())
    }

    pub fn transfer_spl_to_main_vault(
        ctx: Context<TransferSplToMainVault>,
        // agent id
        agent: [u8; 32],
        // agent's account index
        account: u64,
        // account's user index
        user: u64
    ) -> Result<()> {
        msg!("method invoked.");
        let user_token_account = &ctx.accounts.user_token_account;
        let amount = user_token_account.amount;

        let bump_seed = ctx.bumps.user_vault;
        let signer_seeds: &[&[&[u8]]] = &[&[
            USER_VAULTS_SEED,
            &agent,
            &account.to_be_bytes(),
            &user.to_be_bytes(),
            &[bump_seed]
        ]];

        ctx.accounts.ensure_account_exist()?;
        token::transfer(ctx.accounts.into_transfer_context().with_signer(signer_seeds), amount)?;

        Ok(())
    }

    pub fn withdraw_spl(
        ctx: Context<WithdrawSpl>,
        amount: u64,
        signature: [u8; 64],
    ) -> Result<()> {
        let assetman = &ctx.accounts.configs;

        let index = load_current_index_checked(&ctx.accounts.instructions.to_account_info())?;
        require!(index >= 1, CustomError::VerifyFirst);

        let message = get_withdraw_message(
            &ctx.accounts.mint.key().to_string(),
            &ctx.accounts.destination.key(),
            amount
        );

        let ix = load_instruction_at_checked(index as usize - 1, &ctx.accounts.instructions.to_account_info())?;
        ed25519::verify(&ix, &signature, &message, &assetman.withdraw_author.to_bytes())?;

        let bump_seed = ctx.bumps.main_vault;
        let signer_seeds: &[&[&[u8]]] = &[&[MAIN_VAULTS_SEED, &[bump_seed]]];

        ctx.accounts.ensure_account_exist()?;
        ctx.accounts.ensure_sufficient_balance(amount)?;
        token::transfer(ctx.accounts.into_transfer_context().with_signer(signer_seeds), amount)?;

        Ok(())
    }

}

// Define the Configs account
#[account]
#[derive(Default)]
pub struct Configs {
    admins: Vec<Pubkey>,
    withdraw_author: Pubkey,
}

// Error checking functions remain within the Configs struct
impl Configs {
    pub fn is_admin(&self, user: &AccountInfo) -> Result<()> {
        if !self.admins.contains(&user.key()) {
            return Err(CustomError::AdminRestricted.into());
        }
        Ok(())
    }
}

// Define account contexts for instructions
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + 32 + 32 * 10,
        seeds = [ASSETMAN_CONFIG_SEEDS], // Replace "configs" with your desired seed
        bump
    )]
    pub configs: Account<'info, Configs>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminAdd<'info> {
    #[account(mut)]
    pub configs: Account<'info, Configs>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct AdminDelete<'info> {
    #[account(mut)]
    pub configs: Account<'info, Configs>,
    pub admin: Signer<'info>,  // This represents the caller, who must be an admin
}

#[derive(Accounts)]
pub struct SetWithdrawAuthority<'info> {
    #[account(
        mut,
        seeds = [ASSETMAN_CONFIG_SEEDS], // Replace "configs" with your desired seed
        bump
    )]
    pub configs: Account<'info, Configs>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(agent: [u8; 32], account: u64, user: u64)]
pub struct TransferSolToMainVault<'info> {
    #[account(
        mut,
        seeds = [USER_VAULTS_SEED, &agent, &account.to_be_bytes(), &user.to_be_bytes()],
        bump
    )]
    /// CHECK: this is pda account
    pub user_vault: AccountInfo<'info>,

    #[account(
        mut,
        seeds = [MAIN_VAULTS_SEED],
        bump
    )]
    /// CHECK: this is pda account
    pub main_vault: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawSol<'info> {
    #[account(
        seeds = [ASSETMAN_CONFIG_SEEDS], // Replace "configs" with your desired seed
        bump
    )]
    pub configs: Account<'info, Configs>,

    #[account(
        mut,
        seeds = [MAIN_VAULTS_SEED],
        bump
    )]
    /// CHECK: this is pda account
    pub main_vault: AccountInfo<'info>,

    #[account(mut)]
    /// CHECK: it is ok
    pub destination: AccountInfo<'info>,

    /// CHECK: InstructionsSysvar account
    instructions: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(agent: [u8; 32], account: u64, user: u64)]
pub struct TransferSplToMainVault<'info> {
    #[account(signer)]
    /// CHECK: this is transaction signer
    pub signer: AccountInfo<'info>,

    #[account(
        mut,
        seeds = [USER_VAULTS_SEED, &agent, &account.to_be_bytes(), &user.to_be_bytes()],
        bump
    )]
    /// CHECK: this is pda account
    pub user_vault: AccountInfo<'info>,

    #[account(
        mut,
        seeds = [MAIN_VAULTS_SEED],
        bump
    )]
    /// CHECK: this is pda account
    pub main_vault: AccountInfo<'info>,


    #[account(
        mut,
    // constraint = user_token_account.mint == mint.key() @ CustomError::MintMismatch
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(
        mut,
    // constraint = *main_vault_token_account.owner == mint.key() @ CustomError::MintMismatch
    )]
    // pub main_vault_token_account: Account<'info, TokenAccount>,
    /// CHECK:
    pub main_vault_token_account: AccountInfo<'info>,

    #[account(
        mut,
        constraint = mint.supply > 0 @ CustomError::InvalidMint
    )]
    pub mint: Account<'info, Mint>,

    #[account(address = system_program::ID)]
    pub system_program: Program<'info, System>,

    #[account(address = token::ID)]
    pub token_program: Program<'info, Token>,

    #[account(address = associated_token::ID)]
    pub associated_token_program: Program<'info, AssociatedToken>
}

impl<'info> TransferSplToMainVault<'info> {
    fn ensure_account_exist(&self) -> Result<()> {
        // Derive the expected associated token account PDA
        let (expected_pda, _bump) = Pubkey::find_program_address(
            &[
                self.main_vault.key.as_ref(),
                token::ID.as_ref(),
                self.mint.key().as_ref(),
            ],
            &associated_token::ID,
        );

        //Check if the provided account matches the derived PDA
        if self.main_vault_token_account.key() != expected_pda {
            return Err(ProgramError::InvalidAccountData.into());
        }

        // Check if the main_vault_token_account is initialized, if not, initialize it
        if self.main_vault_token_account.to_account_info().data_is_empty() {
            let cpi_accounts = associated_token::Create {
                payer: self.signer.to_account_info(),
                mint: self.mint.to_account_info(),
                authority: self.main_vault.to_account_info(),
                system_program: self.system_program.to_account_info(),
                token_program: self.token_program.to_account_info(),
                associated_token: self.main_vault_token_account.to_account_info(),
            };
            // Create the associated token account
            let cpi_context = CpiContext::new(
                self.associated_token_program.to_account_info(),
                cpi_accounts
            );
            let _ = associated_token::create(cpi_context);
        }

        Ok(())
    }

    fn into_transfer_context(&self) -> CpiContext<'info, 'info, 'info, 'info, token::Transfer<'info>> {
        let cpi_accounts = token::Transfer {
            from: self.user_token_account.to_account_info(),
            to: self.main_vault_token_account.to_account_info(),
            authority: self.user_vault.to_account_info(),
        };
        CpiContext::new(self.token_program.to_account_info(), cpi_accounts)
    }
}

#[derive(Accounts)]
pub struct WithdrawSpl<'info> {
    #[account(signer)]
    /// CHECK: this is transaction signer
    pub signer: AccountInfo<'info>,

    #[account(
        seeds = [ASSETMAN_CONFIG_SEEDS],
        bump
    )]
    pub configs: Account<'info, Configs>,

    #[account(
        mut,
        seeds = [MAIN_VAULTS_SEED],
        bump
    )]
    /// CHECK: this is pda account
    pub main_vault: AccountInfo<'info>,

    #[account(
        mut,
        constraint = main_vault_token_account.mint == mint.key() @ CustomError::MintMismatch
    )]
    pub main_vault_token_account: Account<'info, TokenAccount>,

    /// CHECK: this is destination token owner account
    pub destination: AccountInfo<'info>,

    #[account(
        mut,
    // constraint = destination_token_account.mint == mint.key() @ CustomError::MintMismatch
    )]
    /// CHECK: will check in method handler
    pub destination_token_account: AccountInfo<'info>,

    #[account(
        constraint = mint.supply > 0 @ CustomError::InvalidMint
    )]
    pub mint: Account<'info, Mint>,

    /// CHECK: InstructionsSysvar account
    pub instructions: UncheckedAccount<'info>,

    #[account(address = system_program::ID)]
    pub system_program: Program<'info, System>,

    #[account(address = token::ID)]
    pub token_program: Program<'info, Token>,

    #[account(address = associated_token::ID)]
    pub associated_token_program: Program<'info, AssociatedToken>
}

impl<'info> WithdrawSpl<'info> {
    fn ensure_account_exist(&self) -> Result<()> {
        // Derive the expected associated token account PDA
        let (expected_pda, _bump) = Pubkey::find_program_address(
            &[
                self.destination.key.as_ref(),
                token::ID.as_ref(),
                self.mint.key().as_ref(),
            ],
            &associated_token::ID,
        );

        //Check if the provided account matches the derived PDA
        if self.destination_token_account.key() != expected_pda {
            return Err(ProgramError::InvalidAccountData.into());
        }

        // Check if the main_vault_token_account is initialized, if not, initialize it
        if self.destination_token_account.to_account_info().data_is_empty() {
            let cpi_accounts = associated_token::Create {
                payer: self.signer.to_account_info(),
                mint: self.mint.to_account_info(),
                associated_token: self.destination_token_account.to_account_info(),
                authority: self.destination.to_account_info(),
                system_program: self.system_program.to_account_info(),
                token_program: self.token_program.to_account_info(),
            };
            // Create the associated token account
            let cpi_context = CpiContext::new(
                self.associated_token_program.to_account_info(),
                cpi_accounts
            );
            let _ = associated_token::create(cpi_context);
        }

        Ok(())
    }

    fn ensure_sufficient_balance(&self, expected: u64) -> Result<()> {
        // Get the balance of the main_vault_token_account
        let balance = self.main_vault_token_account.amount;

        // Check if the amount to withdraw is less than or equal to the balance
        require!(balance >= expected, CustomError::InsufficientFunds);

        Ok(())
    }

    fn into_transfer_context(&self) -> CpiContext<'info, 'info, 'info, 'info, token::Transfer<'info>> {
        let cpi_accounts = token::Transfer {
            from: self.main_vault_token_account.to_account_info(),
            to: self.destination_token_account.to_account_info(),
            authority: self.main_vault.to_account_info(),
        };
        CpiContext::new(self.token_program.to_account_info(), cpi_accounts)
    }
}

// Define custom errors
#[error_code]
pub enum CustomError {
    #[msg("Admin restricted method")]
    AdminRestricted,
    #[msg("Duplicate")]
    DuplicateError,
    #[msg("EmptyAdmin")]
    EmptyAdmin,
    #[msg("Unauthorized access")]
    Unauthorized,
    #[msg("Missing data")]
    MissingData,
    #[msg("Verify first.")]
    VerifyFirst,
    #[msg("Insufficient funds.")]
    InsufficientFunds,
    #[msg("Invalid mint.")]
    InvalidMint,
    #[msg("Mint mismatch.")]
    MintMismatch,
}