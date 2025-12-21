#![allow(unexpected_cfgs)]

mod ed25519;

use anchor_lang::{prelude::*, system_program};
use anchor_lang::system_program::{transfer, Transfer};
use anchor_lang::solana_program::sysvar::rent::Rent;
use anchor_spl::associated_token::{self, AssociatedToken};
use anchor_spl::token::{self, Mint, Token, TokenAccount};
use anchor_lang::solana_program::sysvar::{
    self, 
    instructions::{load_current_index_checked, load_instruction_at_checked}
};
use bs58;

const ASSETMAN_CONFIG_V1_SEEDS: &[u8] = b"assetman-configs";
const ASSETMAN_CONFIG_SEEDS: &[u8] = b"assetman-configs-v2";
const MAIN_VAULTS_SEED: &[u8] = b"main-vault";
const USER_VAULTS_SEED: &[u8] = b"user-vault";
const WITHDRAW_ID_SEED: &[u8] = b"withdraw-id";
const MAX_WITHDRAWER_LEN: usize = 10;

declare_id!("YHXAM22ivWgtn3qk4bmX64dREsZbRp6gYd6MfqFPjG5");

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
    pub fn initialize(ctx: Context<Initialize>, frost_pubkey: Pubkey) -> Result<()> {
        let configs = &mut ctx.accounts.configs;
        configs.admin = ctx.accounts.admin.key();

        require!(frost_pubkey != Pubkey::default(), CustomError::MissingData);
        configs.frost_pubkey = frost_pubkey;
        
        Ok(())
    }

    pub fn migrate_configs(ctx: Context<MigrateConfigs>) -> Result<()> {
        let old = &ctx.accounts.old_configs;
        let new = &mut ctx.accounts.new_configs;

        new.admin = old.admin;
        new.withdrawers = old.withdrawers.clone();
        new.frost_pubkey = old.frost_pubkey;
        new.paused = false;

        Ok(())
    }

    pub fn set_pause(ctx: Context<SetPause>, paused: bool) -> Result<()> {
        ctx.accounts.configs.paused = paused;
        Ok(())
    }

    // Transfer admin role to new PubKey
    pub fn transfer_admin(ctx: Context<TransferAdmin>, new_admin: Pubkey) -> Result<()> {
        let configs = &mut ctx.accounts.configs;

        require!(new_admin != Pubkey::default(), CustomError::MissingData);
        configs.admin = new_admin;

        Ok(())
    }

    // Add a new withdrawer to the Configs
    pub fn withdrawer_add(ctx: Context<WithdrawerAdd>, new_withdrawer: Pubkey) -> Result<()> {
        let configs = &mut ctx.accounts.configs;
        require!(!configs.withdrawers.contains(&new_withdrawer), CustomError::DuplicateError);
        require!(configs.withdrawers.len() < MAX_WITHDRAWER_LEN, CustomError::OverflowError);

        configs.withdrawers.push(new_withdrawer);
        Ok(())
    }

    pub fn withdrawer_delete(ctx: Context<WithdrawerDelete>, withdrawer_to_remove: Pubkey) -> Result<()> {
        let configs = &mut ctx.accounts.configs;
        let wr_index = configs.withdrawers.iter().position(|&wr| wr == withdrawer_to_remove);
        require!(wr_index.is_some(), CustomError::MissingData);
        
        configs.withdrawers.remove(wr_index.unwrap());
        Ok(())
    }

    pub fn set_frost_pubkey(ctx: Context<SetFrostPubkey>, frost_pubkey: Pubkey) -> Result<()> {
        let configs = &mut ctx.accounts.configs;

        require!(frost_pubkey != Pubkey::default(), CustomError::MissingData);
        configs.frost_pubkey = frost_pubkey;

        Ok(())
    }

    pub fn transfer_sol_to_main_vault(
        ctx: Context<TransferSolToMainVault>,
        salt: [u8; 32],
    ) -> Result<()> {
        let vault = &ctx.accounts.user_vault;
        let vault_lamports = **vault.lamports.borrow();

        let bump_seed = ctx.bumps.user_vault;
        let signer_seeds: &[&[&[u8]]] = &[&[
            USER_VAULTS_SEED,
            &salt,
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
        ed25519::verify(&ix, &signature, &message, &assetman.frost_pubkey.to_bytes())?;

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
        salt: [u8; 32]
    ) -> Result<()> {
        let user_token_account = &ctx.accounts.user_token_account;
        let amount = user_token_account.amount;

        let bump_seed = ctx.bumps.user_vault;
        let signer_seeds: &[&[&[u8]]] = &[&[
            USER_VAULTS_SEED,
            &salt,
            &[bump_seed]
        ]];

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
        ed25519::verify(&ix, &signature, &message, &assetman.frost_pubkey.to_bytes())?;

        // withdraw_id check
        require!(!ctx.accounts.withdraw_id_record.used, CustomError::Unauthorized);
        ctx.accounts.withdraw_id_record.used = true;

        // Token transfer pre-checks
        ctx.accounts.ensure_sufficient_balance(amount)?;
        
        let bump_seed = ctx.bumps.main_vault;
        let signer_seeds: &[&[&[u8]]] = &[&[MAIN_VAULTS_SEED, &[bump_seed]]];

        token::transfer(ctx.accounts.into_transfer_context().with_signer(signer_seeds), amount)?;
        Ok(())
    }

    pub fn emergency_withdraw_sol(
        ctx: Context<EmergencyWithdrawSol>,
        amount: u64,
    ) -> Result<()> {
        let vault = &ctx.accounts.main_vault;

        let vault_lamports = **vault.lamports.borrow();
        let rent_exempt_minimum = Rent::get()?.minimum_balance(vault.data_len());
        let transferable = vault_lamports.saturating_sub(rent_exempt_minimum);

        require!(amount <= transferable, CustomError::InsufficientFunds);

        let bump = ctx.bumps.main_vault;
        let signer_seeds: &[&[&[u8]]] = &[&[
            MAIN_VAULTS_SEED,
            &[bump],
        ]];

        let cpi_ctx = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            Transfer {
                from: ctx.accounts.main_vault.to_account_info(),
                to: ctx.accounts.destination.to_account_info(),
            },
        )
        .with_signer(signer_seeds);

        transfer(cpi_ctx, amount)?;

        emit!(EmergencyWithdraw {
            admin: ctx.accounts.admin.key(),
            mint: None,
            amount,
            destination: ctx.accounts.destination.key(),
        });

        Ok(())
    }

    pub fn emergency_withdraw_spl(
        ctx: Context<EmergencyWithdrawSpl>,
        amount: u64,
    ) -> Result<()> {
        require!(
            ctx.accounts.main_vault_token_account.amount >= amount,
            CustomError::InsufficientFunds
        );

        let bump = ctx.bumps.main_vault;
        let signer_seeds: &[&[&[u8]]] = &[&[
            MAIN_VAULTS_SEED,
            &[bump],
        ]];

        token::transfer(
            ctx.accounts
                .into_transfer_context()
                .with_signer(signer_seeds),
            amount,
        )?;

        emit!(EmergencyWithdraw {
            admin: ctx.accounts.admin.key(),
            mint: Some(ctx.accounts.mint.key()),
            amount,
            destination: ctx.accounts.destination.key(),
        });

        Ok(())
    }

    // todo :: this is for development phase remove for mainnet
    // it is`nt possible to do it bulk in program because you need to pass them in context
    
    // pub fn reset_withdraw_sol_id(
    //     ctx: Context<ResetWithdrawSolId>,
    // ) -> Result<()> {
    //     ctx.accounts.withdraw_id_record.used = false;
    //     Ok(())
    // }
}

// Define the legacy Configs account
#[account]
#[derive(Default, InitSpace)]
pub struct ConfigsV1 {
    admin: Pubkey,
    #[max_len(MAX_WITHDRAWER_LEN)]
    withdrawers: Vec<Pubkey>,
    frost_pubkey: Pubkey,
}

// Define the Configs account
#[account]
#[derive(Default, InitSpace)]
pub struct Configs {
    admin: Pubkey,
    #[max_len(MAX_WITHDRAWER_LEN)]
    withdrawers: Vec<Pubkey>,
    frost_pubkey: Pubkey,
    paused: bool,
}

impl Configs {
    pub fn is_admin(&self, user: &AccountInfo) -> Result<()> {
        require!(self.admin == user.key(), CustomError::AdminRestricted);
        Ok(())
    }

    pub fn is_withdrawer(&self, user: &AccountInfo) -> Result<()> {
        require!(self.withdrawers.contains(&user.key()), CustomError::UnauthorizedWithdrawer);
        Ok(())
    }
}

// Define account contexts for instructions
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + Configs::INIT_SPACE,
        seeds = [ASSETMAN_CONFIG_SEEDS],
        bump
    )]
    pub configs: Account<'info, Configs>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct MigrateConfigs<'info> {
    #[account(seeds = [ASSETMAN_CONFIG_V1_SEEDS], bump)]
    pub old_configs: Account<'info, ConfigsV1>,

    #[account(
        init,
        payer = admin,
        space = 8 + Configs::INIT_SPACE,
        seeds = [ASSETMAN_CONFIG_SEEDS],
        bump
    )]
    pub new_configs: Account<'info, Configs>,

    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetPause<'info> {
    #[account(
        mut, 
        seeds = [ASSETMAN_CONFIG_SEEDS], 
        bump,
        constraint = configs.admin == admin.key() @ CustomError::AdminRestricted
    )]
    pub configs: Account<'info, Configs>,

    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct TransferAdmin<'info> {
    #[account(
        mut, 
        constraint = configs.admin == admin.key() @ CustomError::AdminRestricted
    )]
    pub configs: Account<'info, Configs>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct WithdrawerAdd<'info> {
    #[account(
        mut,
        constraint = configs.admin == admin.key() @ CustomError::AdminRestricted
    )]
    pub configs: Account<'info, Configs>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct WithdrawerDelete<'info> {
    #[account(
        mut,
        constraint = configs.admin == admin.key() @ CustomError::AdminRestricted
    )]
    pub configs: Account<'info, Configs>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetFrostPubkey<'info> {
    #[account(
        mut, 
        seeds = [ASSETMAN_CONFIG_SEEDS], 
        bump,
        constraint = configs.admin == admin.key() @ CustomError::AdminRestricted
    )]
    pub configs: Account<'info, Configs>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(salt: [u8; 32])]
pub struct TransferSolToMainVault<'info> {
    #[account(mut, seeds = [USER_VAULTS_SEED, &salt], bump)]
    pub user_vault: AccountInfo<'info>,

    #[account(mut, seeds = [MAIN_VAULTS_SEED], bump)]
    pub main_vault: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(amount:u64, withdraw_id: u64, signature: [u8; 64])]
pub struct WithdrawSol<'info> {
    #[account(
        seeds = [ASSETMAN_CONFIG_SEEDS], 
        bump,
        constraint = !configs.paused @ CustomError::ProgramPaused
    )]
    pub configs: Account<'info, Configs>,

    #[account(mut, seeds = [MAIN_VAULTS_SEED], bump)]
    pub main_vault: SystemAccount<'info>,

    #[account(mut)]
    pub destination: SystemAccount<'info>,

    #[account(address = sysvar::instructions::ID)]
    pub instructions: UncheckedAccount<'info>,

    /// CHECK: PDA withdraw_id record, checked in code
    /// init_if_needed change to init in mainnet
    #[account(
        init,
        payer = signer,
        space = 8 + 1,
        seeds = [WITHDRAW_ID_SEED, &withdraw_id.to_le_bytes()],
        bump,
    )]
    pub withdraw_id_record: Account<'info, WithdrawIDRecord>,

    #[account(
        mut, 
        signer,
        constraint = configs.withdrawers.contains(&signer.key()) @ CustomError::UnauthorizedWithdrawer
    )]
    pub signer: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(salt: [u8; 32])]
pub struct TransferSplToMainVault<'info> {
    #[account(signer, mut)]
    pub signer: AccountInfo<'info>,

    #[account(mut, seeds = [USER_VAULTS_SEED, &salt], bump)]
    pub user_vault: AccountInfo<'info>,

    #[account(mut, seeds = [MAIN_VAULTS_SEED], bump)]
    pub main_vault: AccountInfo<'info>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = user_vault
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(
        init_if_needed,
        payer = signer,
        associated_token::mint = mint,
        associated_token::authority = main_vault
    )]
    pub main_vault_token_account: Account<'info, TokenAccount>,

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
    #[account(
        mut, 
        signer,
        constraint = configs.withdrawers.contains(&signer.key()) @ CustomError::UnauthorizedWithdrawer
    )]
    pub signer: AccountInfo<'info>,

    #[account(
        seeds = [ASSETMAN_CONFIG_SEEDS], 
        bump,
        constraint = !configs.paused @ CustomError::ProgramPaused
    )]
    pub configs: Account<'info, Configs>,

    #[account(mut, seeds = [MAIN_VAULTS_SEED], bump)]
    pub main_vault: AccountInfo<'info>,

    #[account(
        mut, 
        associated_token::mint = mint,
        associated_token::authority = main_vault,
    )]
    pub main_vault_token_account: Account<'info, TokenAccount>,

    pub destination: AccountInfo<'info>,

    #[account(
        init,
        payer = signer,
        associated_token::mint = mint,
        associated_token::authority = destination,
    )]
    pub destination_token_account: Account<'info, TokenAccount>,

    #[account(constraint = mint.supply > 0 @ CustomError::InvalidMint)]
    pub mint: Account<'info, Mint>,

    #[account(address = sysvar::instructions::ID)]
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
#[instruction(amount: u64)]
pub struct EmergencyWithdrawSol<'info> {
    #[account(
        seeds = [ASSETMAN_CONFIG_SEEDS],
        bump,
        constraint = configs.admin == admin.key() @ CustomError::AdminRestricted
    )]
    pub configs: Account<'info, Configs>,

    pub admin: Signer<'info>,

    #[account(
        mut,
        seeds = [MAIN_VAULTS_SEED],
        bump
    )]
    pub main_vault: SystemAccount<'info>,

    #[account(mut)]
    pub destination: SystemAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(amount: u64)]
pub struct EmergencyWithdrawSpl<'info> {
    #[account(
        seeds = [ASSETMAN_CONFIG_SEEDS],
        bump,
        constraint = configs.admin == admin.key() @ CustomError::AdminRestricted
    )]
    pub configs: Account<'info, Configs>,

    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        mut,
        seeds = [MAIN_VAULTS_SEED],
        bump
    )]
    pub main_vault: AccountInfo<'info>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = main_vault
    )]
    pub main_vault_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub destination: AccountInfo<'info>,

    #[account(
        init_if_needed,
        payer = admin,
        associated_token::mint = mint,
        associated_token::authority = destination
    )]
    pub destination_token_account: Account<'info, TokenAccount>,

    pub mint: Account<'info, Mint>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

impl<'info> EmergencyWithdrawSpl<'info> {
    fn into_transfer_context(
        &self,
    ) -> CpiContext<'info, 'info, 'info, 'info, token::Transfer<'info>> {
        let cpi_accounts = token::Transfer {
            from: self.main_vault_token_account.to_account_info(),
            to: self.destination_token_account.to_account_info(),
            authority: self.main_vault.to_account_info(),
        };
        CpiContext::new(self.token_program.to_account_info(), cpi_accounts)
    }
}

#[event]
pub struct EmergencyWithdraw {
    pub admin: Pubkey,
    pub mint: Option<Pubkey>,
    pub amount: u64,
    pub destination: Pubkey,
}

// #[derive(Accounts)]
// #[instruction(withdraw_id: u64)]
// pub struct ResetWithdrawSolId<'info> {
//     #[account(mut)]
//     pub admin: Signer<'info>,

//     #[account(
//         mut,
//         seeds = [WITHDRAW_ID_SEED, &withdraw_id.to_le_bytes()],
//         bump,
//     )]
//     pub withdraw_id_record: Account<'info, WithdrawIDRecord>,

//     pub system_program: Program<'info, System>,
// }


// Define custom errors
#[error_code]
pub enum CustomError {
    #[msg("Admin restricted method")]
    AdminRestricted,
    #[msg("Unauthorized withdrawer")]
    UnauthorizedWithdrawer,
    #[msg("Duplicate entry")]
    DuplicateError,
    #[msg("Overflow error")]
    OverflowError,
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
    #[msg("Program is paused")]
    ProgramPaused,
}