use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    ed25519_program,
    instruction::Instruction,
};
use bytemuck::{bytes_of, Pod, Zeroable};

pub const PUBKEY_SERIALIZED_SIZE: usize = 32;
pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;
pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 14;
pub const SIGNATURE_OFFSETS_START: usize = 2;
pub const DATA_START: usize = SIGNATURE_OFFSETS_SERIALIZED_SIZE + SIGNATURE_OFFSETS_START;

#[derive(Default, Debug, Copy, Clone, Zeroable, Pod, Eq, PartialEq)]
#[repr(C)]
pub struct Ed25519SignatureOffsets {
    pub signature_offset: u16,
    pub signature_instruction_index: u16,
    pub public_key_offset: u16,
    pub public_key_instruction_index: u16,
    pub message_data_offset: u16,
    pub message_data_size: u16,
    pub message_instruction_index: u16,
}

pub fn verify(
    ix: &Instruction,
    signature: &[u8; 64],
    message: &[u8],
    public_key: &[u8; 32],
) -> Result<()> {
    require_keys_eq!(ix.program_id, ed25519_program::ID, ErrorCode::InvalidEd25519Program);

    let mut instruction_data = Vec::with_capacity(
        DATA_START + SIGNATURE_SERIALIZED_SIZE + PUBKEY_SERIALIZED_SIZE + message.len(),
    );

    let num_signatures: u8 = 1;
    let _padding: u8 = 0;

    // offset calculations
    let public_key_offset = DATA_START;
    let signature_offset = public_key_offset + PUBKEY_SERIALIZED_SIZE;
    let message_data_offset = signature_offset + SIGNATURE_SERIALIZED_SIZE;

    // add padding (alignment for the struct)
    instruction_data.push(num_signatures);
    instruction_data.push(_padding);

    let offsets = Ed25519SignatureOffsets {
        signature_offset: signature_offset as u16,
        signature_instruction_index: u16::MAX,
        public_key_offset: public_key_offset as u16,
        public_key_instruction_index: u16::MAX,
        message_data_offset: message_data_offset as u16,
        message_data_size: message.len() as u16,
        message_instruction_index: u16::MAX,
    };

    instruction_data.extend_from_slice(bytes_of(&offsets));

    debug_assert_eq!(instruction_data.len(), public_key_offset);
    instruction_data.extend_from_slice(public_key);

    debug_assert_eq!(instruction_data.len(), signature_offset);
    instruction_data.extend_from_slice(signature);

    debug_assert_eq!(instruction_data.len(), message_data_offset);
    instruction_data.extend_from_slice(message);

    require!(
        instruction_data == ix.data,
        ErrorCode::InvalidSignature
    );

    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid signature")]
    InvalidSignature,
    #[msg("Invalid ed25519_program")]
    InvalidEd25519Program,
}
