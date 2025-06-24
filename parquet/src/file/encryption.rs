// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//! Module for Parquet encryption types and helpers

use std::convert::TryFrom;
use std::io::{Cursor, Read, Write};

use aes_gcm::aead::AeadMutInPlace;
use aes_gcm::{AeadCore as _, Aes256Gcm, KeyInit as _, Nonce};
use aes_gcm::{KeySizeUser, Tag};
use rand::{rngs::OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_224};

use crate::errors::{ParquetError, Result};

use crate::file::{PARQUET_MAGIC, PARQUET_MAGIC_ENCRYPTED_FOOTER};

use super::metadata::FileEncryptionInfo;

/// An identifier, supplied by the user, to identify a parquet encryption key.  Plausible values are
/// "1", "2", "3", etc.
pub type ParquetEncryptionKeyId = String;

/// A key id paired up with its key.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ParquetEncryptionKeyInfo {
    /// The encryption key id
    pub key_id: ParquetEncryptionKeyId,
    /// The encryption key
    pub key: ParquetEncryptionKey,
}

/// Tells what mode (and also the key value(s)) a file is to be encrypted in (when writing) or is
/// permitted to be encrypted in (when reading).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ParquetEncryptionMode {
    /// Means the file is unencrypted
    Unencrypted,
    /// Means the file is encrypted with encrypted footer mode.  The same
    /// key is used for all the columns too, in this implementation.
    EncryptedFooter(ParquetEncryptionKeyInfo),
}

/// Describes general parquet encryption configuration -- new files are encrypted with the
/// write_key(), but old files can be decrypted with any of the valid read keys.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ParquetEncryptionConfig {
    // The last mode is the write mode (i.e. it has the write key), and all the prior modes are
    // valid read modes (i.e. valid read keys, or Unencrypted mode, if a user turned on encryption
    // but hasn't key-rotated unencrypted files away yet).
    keys: Vec<ParquetEncryptionMode>,
}

impl ParquetEncryptionConfig {
    /// Returns None if keys is empty().  ParquetEncryptionConfig is supposed to always contain one
    /// or more values.
    pub fn new(keys: Vec<ParquetEncryptionMode>) -> Option<ParquetEncryptionConfig> {
        if keys.is_empty() {
            None
        } else {
            Some(ParquetEncryptionConfig { keys })
        }
    }

    /// Returns the write key (the last key).
    pub fn write_key(&self) -> &ParquetEncryptionMode {
        self.keys.last().unwrap()
    }

    /// Returns the read keys (including the write key).
    pub fn read_keys(&self) -> &[ParquetEncryptionMode] {
        self.keys.as_slice()
    }
}

/// The length of a Sha3-224 hash.  This is not part of the Parquet encryption format.
pub const PARQUET_KEY_HASH_LENGTH: usize = 28;
/// The length of an Aes256Gcm Parquet encryption key i.e. 32 bytes.
pub const PARQUET_KEY_SIZE: usize = 32;

/// Describes how we encrypt or encrypted the Parquet files.  Right now (in this implementation)
/// files can only be encrypted in "encrypted footer mode" with the footer and columns all encrypted
/// with the same key.

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub struct ParquetEncryptionKey {
    /// The key we use for all parts and components of the Parquet files.
    pub key: [u8; PARQUET_KEY_SIZE],
}

impl ParquetEncryptionKey {
    /// Constructs a zero-initialized ParquetEncryption key.
    pub fn default() -> ParquetEncryptionKey {
        ParquetEncryptionKey {
            key: Default::default(),
        }
    }

    /// Returns the key size in bytes.
    pub fn key_size() -> usize {
        Aes256Gcm::key_size()
    }

    /// Generates a new cryptographically random parquet encryption key.
    pub fn generate_key() -> ParquetEncryptionKey {
        let key = Aes256Gcm::generate_key(OsRng);
        let mut result = ParquetEncryptionKey::default();
        result.key.copy_from_slice(&key);
        result
    }

    /// Returns self typedd as an `aes_gcm::Key<Aes256Gcm>`
    pub fn to_aes256_gcm_key(&self) -> aes_gcm::Key<Aes256Gcm> {
        let mut result = aes_gcm::Key::<Aes256Gcm>::default();
        let r: &mut [u8] = &mut result;
        r.copy_from_slice(&self.key);
        result
    }

    /// Computes a "hash" of the key -- returning a Sha3-224 hash, for what it's worth -- useful as
    /// a key identifier.  This is not part of the Parquet encryption format.
    pub fn compute_key_hash(&self) -> [u8; PARQUET_KEY_HASH_LENGTH] {
        let mut hasher = Sha3_224::new();
        hasher.update(&self.key);
        let result = hasher.finalize();
        result.into()
    }
}

/// The length of a RandomFileIdentifier, in bytes.
pub const AAD_FILE_UNIQUE_SIZE: usize = 20;
/// A random buffer used to uniquely identify a file.
pub type RandomFileIdentifier = [u8; AAD_FILE_UNIQUE_SIZE];

const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
/// The value is 32.  A 4-byte length field, 12-byte nonce, 16-byte tag.
pub const USUAL_ENCRYPTION_OVERHEAD: usize = 4 + NONCE_SIZE + TAG_SIZE;

/// Generates a unique identifier for a file, used in generating aad's.
pub fn generate_random_file_identifier() -> RandomFileIdentifier {
    let mut v = [0u8; AAD_FILE_UNIQUE_SIZE];
    OsRng.fill_bytes(&mut v);
    v
}

#[allow(missing_docs)]
#[derive(Clone, Debug)]
pub struct RowGroupColumnEncryptionParams {
    pub encryption_info: FileEncryptionInfo,
    pub row_group_ordinal: i16,
    pub column_ordinal: u16,
}

/// Returns the magic to write at the beginning and end of the file (depending on whether we use
/// footer encryption)
pub fn parquet_magic(is_footer_encrypted: bool) -> [u8; 4] {
    // For now ParquetEncryptionKey only allows footer encryption mode.
    if !is_footer_encrypted {
        PARQUET_MAGIC
    } else {
        PARQUET_MAGIC_ENCRYPTED_FOOTER
    }
}

/// Generates the aad suffix used in the parquet encryption format.  The first element is the
/// length, which is either 25 or 27, depending on if page_ordinal is present.  This could probably
/// just return an `ArrayVec`.
#[inline]
pub fn parquet_aad_suffix(
    file_identifier: &RandomFileIdentifier,
    aad_module_type: u8,
    row_group_ordinal: i16,
    column_ordinal: u16,
    page_ordinal: Option<u16>,
) -> (usize, [u8; 27]) {
    const PAGEFUL_SUFFIX_SIZE: usize = AAD_FILE_UNIQUE_SIZE + 1 + 2 + 2 + 2; // 27
    let mut buf = [0u8; PAGEFUL_SUFFIX_SIZE];
    buf[0..AAD_FILE_UNIQUE_SIZE].copy_from_slice(file_identifier);
    buf[AAD_FILE_UNIQUE_SIZE] = aad_module_type;
    buf[AAD_FILE_UNIQUE_SIZE + 1..AAD_FILE_UNIQUE_SIZE + 3]
        .copy_from_slice(&row_group_ordinal.to_le_bytes());
    buf[AAD_FILE_UNIQUE_SIZE + 3..AAD_FILE_UNIQUE_SIZE + 5]
        .copy_from_slice(&column_ordinal.to_le_bytes());
    if let Some(ordinal) = page_ordinal {
        buf[AAD_FILE_UNIQUE_SIZE + 5..AAD_FILE_UNIQUE_SIZE + 7]
            .copy_from_slice(&ordinal.to_le_bytes());
        (27, buf)
    } else {
        (25, buf)
    }
}

/// Generates the aad suffix used in the parquet encryption format -- for modules that don't have a page ordinal.
#[inline]
pub fn parquet_aad_suffix_no_page(
    file_identifier: &RandomFileIdentifier,
    aad_module_type: u8,
    row_group_ordinal: i16,
    column_ordinal: u16,
) -> [u8; 25] {
    const PAGELESS_SUFFIX_SIZE: usize = AAD_FILE_UNIQUE_SIZE + 1 + 2 + 2; // 25
    let mut buf = [0u8; PAGELESS_SUFFIX_SIZE];
    buf[0..AAD_FILE_UNIQUE_SIZE].copy_from_slice(file_identifier);
    buf[AAD_FILE_UNIQUE_SIZE] = aad_module_type;
    buf[AAD_FILE_UNIQUE_SIZE + 1..AAD_FILE_UNIQUE_SIZE + 3]
        .copy_from_slice(&row_group_ordinal.to_le_bytes());
    buf[AAD_FILE_UNIQUE_SIZE + 3..AAD_FILE_UNIQUE_SIZE + 5]
        .copy_from_slice(&column_ordinal.to_le_bytes());
    buf
}

/// Generates the aad suffix used in the parquet encryption format -- for modules that do have a page ordinal.
#[inline]
pub fn parquet_aad_suffix_with_page(
    file_identifier: &RandomFileIdentifier,
    aad_module_type: u8,
    row_group_ordinal: i16,
    column_ordinal: u16,
    page_ordinal: u16,
) -> [u8; 27] {
    const PAGEFUL_SUFFIX_SIZE: usize = AAD_FILE_UNIQUE_SIZE + 1 + 2 + 2 + 2; // 27
    let mut buf = [0u8; PAGEFUL_SUFFIX_SIZE];
    buf[0..AAD_FILE_UNIQUE_SIZE].copy_from_slice(file_identifier);
    buf[AAD_FILE_UNIQUE_SIZE] = aad_module_type;
    buf[AAD_FILE_UNIQUE_SIZE + 1..AAD_FILE_UNIQUE_SIZE + 3]
        .copy_from_slice(&row_group_ordinal.to_le_bytes());
    buf[AAD_FILE_UNIQUE_SIZE + 3..AAD_FILE_UNIQUE_SIZE + 5]
        .copy_from_slice(&column_ordinal.to_le_bytes());
    buf[AAD_FILE_UNIQUE_SIZE + 5..AAD_FILE_UNIQUE_SIZE + 7]
        .copy_from_slice(&page_ordinal.to_le_bytes());
    buf
}

pub(crate) fn row_group_ordinal_error() -> ParquetError {
    return ParquetError::General(
        "RowGroupMetaData in encrypted file lacks row group ordinal".to_owned(),
    );
}

/// PrepaddedPlaintext simply carries a buf with 16 empty bytes at the front. Then you can append
/// plaintext to it and pass it to encrypt_module, and it can then encrypt in-place and pass to the
/// Write with a single call.
pub struct PrepaddedPlaintext {
    buf: Vec<u8>,
}

impl PrepaddedPlaintext {
    /// Constructs a buf for appending with plaintext and passing to encrypt_module.  It is
    /// recommended that you use the result of self.buf_mut() as a `Write` to append the plaintext.
    pub fn new() -> PrepaddedPlaintext {
        PrepaddedPlaintext { buf: vec![0u8; 16] }
    }
    /// Returns a mutable version of the underlying buffer.
    pub fn buf_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }
}

/// Writes "length (4 bytes) nonce (12 bytes) ciphertext (length - 28 bytes) tag (16 bytes)"
pub fn encrypt_module<W: Write>(
    what: &str,
    w: &mut W,
    encryption_key: &ParquetEncryptionKey,
    mut prepadded: PrepaddedPlaintext,
    aad: &[u8],
) -> Result<()> {
    let mut cipher = Aes256Gcm::new(&encryption_key.to_aes256_gcm_key());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let buf = prepadded.buf_mut();
    let buflen = buf.len();
    let tag: Tag<_>;
    {
        let (front, plaintext) = buf.split_at_mut(4 + NONCE_SIZE);

        let written_len = u32::try_from(buflen - 4 + TAG_SIZE)
            .map_err(|_| general_err!("Error encrypting {}.  Module is too large", what))?;
        front[..4].copy_from_slice(&u32::to_le_bytes(written_len));
        front[4..].copy_from_slice(&nonce);

        tag = cipher
            .encrypt_in_place_detached(&nonce, aad, plaintext)
            .map_err(|_| general_err!("Error encrypting {}", what))?;
    }

    buf.extend_from_slice(&tag);

    w.write_all(buf)?;
    Ok(())
}

/// Decrypts a module.  Expects "length (4 bytes) nonce (12 bytes) ciphertext (length - 28 bytes) tag (16 bytes)".
pub fn decrypt_module<R: Read>(
    what: &str,
    mut r: R,
    encryption_key: &ParquetEncryptionKey,
    aad: &[u8],
) -> Result<Cursor<Vec<u8>>> {
    let mut cipher = Aes256Gcm::new(&encryption_key.to_aes256_gcm_key());

    let buflen = {
        let mut buf = [0; 4];
        r.read_exact(&mut buf)?;
        u32::from_le_bytes(buf)
    };
    let buflen = buflen as usize;
    if buflen < NONCE_SIZE + TAG_SIZE {
        return Err(general_err!(
            "Invalid Parquet file.  Encrypted buffer length too short"
        ));
    }
    let mut buf = vec![0u8; buflen];
    r.read_exact(&mut buf)?;

    let nonce = *Nonce::from_slice(&buf[..NONCE_SIZE]);
    let tag = *Tag::from_slice(&buf[buflen - TAG_SIZE..]);

    cipher
        .decrypt_in_place_detached(&nonce, aad, &mut buf[NONCE_SIZE..buflen - TAG_SIZE], &tag)
        .map_err(|_| general_err!("Error decrypting {}", what))?;

    // Now trim the buf of its trailing tag, and return a Cursor that skips past the nonce.
    // And just to prevent any weirdness, zero out the nonce.
    buf.truncate(buflen - TAG_SIZE);
    buf[..NONCE_SIZE].fill(0);

    let mut cursor = Cursor::new(buf);
    cursor.set_position(NONCE_SIZE as u64);

    Ok(cursor)
}

#[inline]
/// Converts usize to i16, and makes an error message if out of range.
pub fn try_into_row_group_ordinal(row_group_index: usize) -> Result<i16> {
    // Implementation and error message copied from SerializedFileWriter::next_row_group.
    row_group_index.try_into().map_err(|_| {
        ParquetError::General(format!(
            "Parquet does not support more than {} row groups per file (currently: {})",
            i16::MAX,
            row_group_index
        ))
    })
}

#[inline]
/// Converts usize to u16, and makes an error message if out of range.  Should only be used in Parquet encryption code.
pub fn try_into_column_ordinal(column_index: usize) -> Result<u16> {
    // Error message is based on into_row_group_ordinal's, but we should only be invoking this when using Parquet encryption.
    column_index.try_into().map_err(|_| {
        ParquetError::General(format!(
            "Parquet encryption does not support more than {} columns per file (currently: {})",
            u16::MAX,
            column_index
        ))
    })
}

#[inline]
/// Converts usize to i16, and makes an error message if out of range.  TODO: Currently this is called even if we aren't encrypting.
pub fn try_into_page_ordinal(page_ordinal: usize) -> Result<u16> {
    // Implementation and error message copied from SerializedFileWriter::next_row_group.
    page_ordinal.try_into().map_err(|_| {
        ParquetError::General(format!(
            "Parquet does not support more than {} pages per row group column (currently: {})",
            u16::MAX,
            page_ordinal
        ))
    })
}

/// If encryption_info is Some(_), converts to RowGroupColumnEncryptionParams.  Errs if there is a
/// usize -> i16 or usize -> u16 truncation error.  The idea here is we only try the column ordinal
/// conversion if encryption is enabled.
pub fn try_into_encryption_params(
    encryption_info: &Option<FileEncryptionInfo>,
    row_group_idx: usize,
    column_idx: usize,
) -> Result<Option<RowGroupColumnEncryptionParams>> {
    if let Some(ei) = encryption_info {
        let row_group_ordinal = try_into_row_group_ordinal(row_group_idx)?;
        let column_ordinal = try_into_column_ordinal(column_idx)?;

        Ok(Some(RowGroupColumnEncryptionParams {
            encryption_info: ei.clone(),
            row_group_ordinal,
            column_ordinal,
        }))
    } else {
        Ok(None)
    }
}

/// Like `try_into_encryption_params` but where the row_group_ordinal has already been truncated to
/// i16.  The idea here is we only try the column ordinal conversion if encryption is enabled.
pub fn try_into_encryption_params_with_rg_ordinal(
    encryption_info: &Option<FileEncryptionInfo>,
    row_group_ordinal: i16,
    column_idx: usize,
) -> Result<Option<RowGroupColumnEncryptionParams>> {
    if let Some(ei) = encryption_info {
        let column_ordinal = try_into_column_ordinal(column_idx)?;

        Ok(Some(RowGroupColumnEncryptionParams {
            encryption_info: ei.clone(),
            row_group_ordinal,
            column_ordinal,
        }))
    } else {
        Ok(None)
    }
}
