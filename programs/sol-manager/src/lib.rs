#![allow(unexpected_cfgs)]

mod ed25519;

use anchor_lang::{prelude::*, system_program};
use anchor_lang::system_program::{transfer, Transfer};
use anchor_lang::solana_program::sysvar::rent::Rent;
use anchor_spl::associated_token::{self, AssociatedToken};
use anchor_spl::token::{self, Mint, Token, TokenAccount};
use anchor_lang::solana_program::sysvar::instructions::{load_current_index_checked, load_instruction_at_checked};
use anchor_lang::solana_program::program_error::ProgramError;
use bs58;

const MIN_DEPOSIT_LAMPORTS: u64 = 1_000_000;
const ASSETMAN_CONFIG_SEEDS: &[u8] = b"assetman-configs";
const MAIN_VAULTS_SEED: &[u8] = b"main-vault";
const USER_VAULTS_SEED: &[u8] = b"user-vault";
const WITHDRAW_ID_SEED: &[u8] = b"withdraw-id";

declare_id!("CVtFHhvpcXSxAhcmkwtSozQogJonYMZoC9m4BjB1pm3u");

fn get_withdraw_message(token: &str, public_key: &Pubkey, amount: u64, withdraw_id: u64) -> Vec<u8> {
    let base58_address = bs58::encode(public_key.to_bytes()).into_string();
    let formatted_string = format!(
        "allowed withdraw {} {} to address {} with withdraw_id {}",
        amount, token, base58_address, withdraw_id
    );
    formatted_string.as_bytes().to_vec()
}

#[program]
pub mod zex_asset_manager {
    use super::*;

    // Initialize the Configs
    pub fn initialize(ctx: Context<Initialize>, withdraw_author: Pubkey) -> Result<()> {
        let configs = &mut ctx.accounts.configs;
        configs.admins.push(ctx.accounts.admin.key());
        configs.withdraw_author = withdraw_author;
        Ok(())
    }

    // Add a new admin to the Configs
    #[access_control(ctx.accounts.configs.is_admin(&ctx.accounts.admin))]
    pub fn admin_add(ctx: Context<AdminAdd>, new_admin: Pubkey) -> Result<()> {
        let configs = &mut ctx.accounts.configs;
        require!(!configs.admins.contains(&new_admin), CustomError::DuplicateError);
        configs.admins.push(new_admin);
        Ok(())
    }

    #[access_control(ctx.accounts.configs.is_admin(&ctx.accounts.admin))]
    pub fn admin_delete(ctx: Context<AdminDelete>, admin_to_remove: Pubkey) -> Result<()> {
        let configs = &mut ctx.accounts.configs;
        let admin_index = configs.admins.iter().position(|&admin| admin == admin_to_remove);
        require!(admin_index.is_some(), CustomError::MissingData);
        require!(configs.admins.len() > 1, CustomError::EmptyAdmin);
        configs.admins.remove(admin_index.unwrap());
        Ok(())
    }

    #[access_control(ctx.accounts.configs.is_admin(&ctx.accounts.admin))]
    pub fn set_withdraw_authority(ctx: Context<SetWithdrawAuthority>, withdraw_author: Pubkey) -> Result<()> {
        let configs = &mut ctx.accounts.configs;
        configs.withdraw_author = withdraw_author;
        Ok(())
    }

    pub fn transfer_sol_to_main_vault(
        ctx: Context<TransferSolToMainVault>,
        salt: u64,
    ) -> Result<()> {
        let vault = &ctx.accounts.user_vault;
        let vault_lamports = **vault.lamports.borrow();
        require!(vault_lamports > MIN_DEPOSIT_LAMPORTS, CustomError::InsufficientFunds);

        let bump_seed = ctx.bumps.user_vault;
        let signer_seeds: &[&[&[u8]]] = &[&[
            USER_VAULTS_SEED,
            &salt.to_le_bytes(),
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

        transfer(cpi_context, vault_lamports)?;
        Ok(())
    }

    pub fn withdraw_sol(
        ctx: Context<WithdrawSol>,
        amount: u64,
        withdraw_id: u64,
        signature: [u8; 64],
    ) -> Result<()> {
        let assetman = &ctx.accounts.configs;

        // Check instruction index
        let index = load_current_index_checked(&ctx.accounts.instructions.to_account_info())?;
        require!(index >= 1, CustomError::VerifyFirst);

        // Verify signature (message includes withdraw_id)
        let message = get_withdraw_message("SOL", &ctx.accounts.destination.key(), amount, withdraw_id);
        let ix = load_instruction_at_checked(index as usize - 1, &ctx.accounts.instructions.to_account_info())?;
        ed25519::verify(&ix, &signature, &message, &assetman.withdraw_author.to_bytes())?;

        // Check if withdraw_id already used
        require!(!ctx.accounts.withdraw_id_record.used, CustomError::Unauthorized);

        // Mark withdraw_id as used
        ctx.accounts.withdraw_id_record.used = true;

        // Transfer SOL (rent-aware)
        let vault = &ctx.accounts.main_vault;
        let vault_lamports = **vault.lamports.borrow();
        let rent_exempt_minimum = Rent::get()?.minimum_balance(vault.data_len());
        let transferable_lamports = vault_lamports.saturating_sub(rent_exempt_minimum);
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

        transfer(cpi_context, amount)?;
        Ok(())
    }


    pub fn transfer_spl_to_main_vault(
        ctx: Context<TransferSplToMainVault>,
        salt: u64
    ) -> Result<()> {
        let user_token_account = &ctx.accounts.user_token_account;
        let amount = user_token_account.amount;

        let bump_seed = ctx.bumps.user_vault;
        let signer_seeds: &[&[&[u8]]] = &[&[
            USER_VAULTS_SEED,
            &salt.to_le_bytes(),
            &[bump_seed]
        ]];

        ctx.accounts.ensure_account_exist()?;
        token::transfer(ctx.accounts.into_transfer_context().with_signer(signer_seeds), amount)?;
        Ok(())
    }

    pub fn withdraw_spl(
        ctx: Context<WithdrawSpl>,
        amount: u64,
        withdraw_id: u64,
        signature: [u8; 64],
    ) -> Result<()> {
        let assetman = &ctx.accounts.configs;

        // Load instruction index for replay protection
        let index = load_current_index_checked(&ctx.accounts.instructions.to_account_info())?;
        require!(index >= 1, CustomError::VerifyFirst);

        // Build message with withdraw_id included
        let message = get_withdraw_message(
            &ctx.accounts.mint.key().to_string(),
            &ctx.accounts.destination.key(),
            amount,
            withdraw_id,
        );

        // Load prior ed25519 instruction
        let ix = load_instruction_at_checked(index as usize - 1, &ctx.accounts.instructions.to_account_info())?;
        ed25519::verify(&ix, &signature, &message, &assetman.withdraw_author.to_bytes())?;

        // withdraw_id check
        require!(!ctx.accounts.withdraw_id_record.used, CustomError::Unauthorized);
        ctx.accounts.withdraw_id_record.used = true;

        // Token transfer pre-checks
        ctx.accounts.ensure_account_exist()?;
        ctx.accounts.ensure_sufficient_balance(amount)?;
        
        let bump_seed = ctx.bumps.main_vault;
        let signer_seeds: &[&[&[u8]]] = &[&[MAIN_VAULTS_SEED, &[bump_seed]]];

        token::transfer(ctx.accounts.into_transfer_context().with_signer(signer_seeds), amount)?;
        Ok(())
    }

    // todo :: this is for development phase remove for mainnet
    // it is`nt possible to do it bulk in program because you need to pass them in context
    
    pub fn reset_withdraw_sol_id(
        ctx: Context<ResetWithdrawSolId>,
    ) -> Result<()> {
        ctx.accounts.withdraw_id_record.used = false;
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

impl Configs {
    pub fn is_admin(&self, user: &AccountInfo) -> Result<()> {
        require!(self.admins.contains(&user.key()), CustomError::AdminRestricted);
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
        seeds = [ASSETMAN_CONFIG_SEEDS],
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
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetWithdrawAuthority<'info> {
    #[account(mut, seeds = [ASSETMAN_CONFIG_SEEDS], bump)]
    pub configs: Account<'info, Configs>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(salt: u64)]
pub struct TransferSolToMainVault<'info> {
    #[account(mut, seeds = [USER_VAULTS_SEED, &salt.to_le_bytes()], bump)]
    pub user_vault: AccountInfo<'info>,

    #[account(mut, seeds = [MAIN_VAULTS_SEED], bump)]
    pub main_vault: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(amount:u64, withdraw_id: u64, signature: [u8; 64])]
pub struct WithdrawSol<'info> {
    #[account(seeds = [ASSETMAN_CONFIG_SEEDS], bump)]
    pub configs: Account<'info, Configs>,

    #[account(mut, seeds = [MAIN_VAULTS_SEED], bump)]
    pub main_vault: SystemAccount<'info>,

    #[account(mut)]
    pub destination: SystemAccount<'info>,

    pub instructions: UncheckedAccount<'info>,

    /// CHECK: PDA withdraw_id record, checked in code
    /// init_if_needed change to init in mainnet
    #[account(
        init_if_needed,
        payer = signer,
        space = 8 + 1,
        seeds = [WITHDRAW_ID_SEED, &withdraw_id.to_le_bytes()],
        bump,
    )]
    pub withdraw_id_record: Account<'info, WithdrawIDRecord>,

    #[account(mut, signer)]
    pub signer: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(salt: u64)]
pub struct TransferSplToMainVault<'info> {
    #[account(signer)]
    pub signer: AccountInfo<'info>,

    #[account(mut, seeds = [USER_VAULTS_SEED, &salt.to_le_bytes()], bump)]
    pub user_vault: AccountInfo<'info>,

    #[account(mut, seeds = [MAIN_VAULTS_SEED], bump)]
    pub main_vault: AccountInfo<'info>,

    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub main_vault_token_account: AccountInfo<'info>,

    #[account(mut, constraint = mint.supply > 0 @ CustomError::InvalidMint)]
    pub mint: Account<'info, Mint>,

    #[account(address = system_program::ID)]
    pub system_program: Program<'info, System>,

    #[account(address = token::ID)]
    pub token_program: Program<'info, Token>,

    #[account(address = associated_token::ID)]
    pub associated_token_program: Program<'info, AssociatedToken>,
}

impl<'info> TransferSplToMainVault<'info> {
    fn ensure_account_exist(&self) -> Result<()> {
        let (expected_pda, _bump) = Pubkey::find_program_address(
            &[
                self.main_vault.key.as_ref(),
                token::ID.as_ref(),
                self.mint.key().as_ref(),
            ],
            &associated_token::ID,
        );

        if self.main_vault_token_account.key() != expected_pda {
            return Err(ProgramError::InvalidAccountData.into());
        }

        if self.main_vault_token_account.to_account_info().data_is_empty() {
            let cpi_accounts = associated_token::Create {
                payer: self.signer.to_account_info(),
                mint: self.mint.to_account_info(),
                authority: self.main_vault.to_account_info(),
                system_program: self.system_program.to_account_info(),
                token_program: self.token_program.to_account_info(),
                associated_token: self.main_vault_token_account.to_account_info(),
            };
            let cpi_context = CpiContext::new(self.associated_token_program.to_account_info(), cpi_accounts);
            associated_token::create(cpi_context)?;
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
#[instruction(amount:u64, withdraw_id: u64, signature: [u8; 64])]
pub struct WithdrawSpl<'info> {
    #[account(mut, signer)]
    pub signer: AccountInfo<'info>,

    #[account(seeds = [ASSETMAN_CONFIG_SEEDS], bump)]
    pub configs: Account<'info, Configs>,

    #[account(mut, seeds = [MAIN_VAULTS_SEED], bump)]
    pub main_vault: AccountInfo<'info>,

    #[account(mut, constraint = main_vault_token_account.mint == mint.key() @ CustomError::MintMismatch)]
    pub main_vault_token_account: Account<'info, TokenAccount>,

    pub destination: AccountInfo<'info>,

    #[account(mut)]
    pub destination_token_account: AccountInfo<'info>,

    #[account(constraint = mint.supply > 0 @ CustomError::InvalidMint)]
    pub mint: Account<'info, Mint>,

    pub instructions: UncheckedAccount<'info>,
    
    /// init_if_needed change to init in mainnet
    #[account(
        init_if_needed,
        payer = signer,
        space =  8 + 1,
        seeds = [WITHDRAW_ID_SEED, &withdraw_id.to_le_bytes()],
        bump,
    )]
    pub withdraw_id_record: Account<'info, WithdrawIDRecord>,

    #[account(address = system_program::ID)]
    pub system_program: Program<'info, System>,

    #[account(address = token::ID)]
    pub token_program: Program<'info, Token>,

    #[account(address = associated_token::ID)]
    pub associated_token_program: Program<'info, AssociatedToken>,
}

impl<'info> WithdrawSpl<'info> {
    fn ensure_account_exist(&self) -> Result<()> {
        let (expected_pda, _bump) = Pubkey::find_program_address(
            &[
                self.destination.key.as_ref(),
                token::ID.as_ref(),
                self.mint.key().as_ref(),
            ],
            &associated_token::ID,
        );

        if self.destination_token_account.key() != expected_pda {
            return Err(ProgramError::InvalidAccountData.into());
        }

        if self.destination_token_account.to_account_info().data_is_empty() {
            let cpi_accounts = associated_token::Create {
                payer: self.signer.to_account_info(),
                mint: self.mint.to_account_info(),
                associated_token: self.destination_token_account.to_account_info(),
                authority: self.destination.to_account_info(),
                system_program: self.system_program.to_account_info(),
                token_program: self.token_program.to_account_info(),
            };
            let cpi_context = CpiContext::new(self.associated_token_program.to_account_info(), cpi_accounts);
            associated_token::create(cpi_context)?;
        }

        Ok(())
    }

    fn ensure_sufficient_balance(&self, expected: u64) -> Result<()> {
        let balance = self.main_vault_token_account.amount;
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

#[account]
#[derive(Default)]
pub struct WithdrawIDRecord {
    pub used: bool,
}

#[derive(Accounts)]
#[instruction(withdraw_id: u64)]
pub struct ResetWithdrawSolId<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        mut,
        seeds = [WITHDRAW_ID_SEED, &withdraw_id.to_le_bytes()],
        bump,
    )]
    pub withdraw_id_record: Account<'info, WithdrawIDRecord>,

    pub system_program: Program<'info, System>,
}


// Define custom errors
#[error_code]
pub enum CustomError {
    #[msg("Admin restricted method")]
    AdminRestricted,
    #[msg("Duplicate entry")]
    DuplicateError,
    #[msg("No admin available")]
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