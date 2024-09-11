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

use std::convert::TryFrom;
use std::io::{Cursor, Read, Write};

use aes_gcm::aead::AeadMutInPlace;
use aes_gcm::{AeadCore as _, Aes256Gcm, KeyInit as _, Nonce};
use aes_gcm::{KeySizeUser, Tag};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rand::{rngs::OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_224};

use crate::errors::{ParquetError, Result};

use crate::file::{PARQUET_MAGIC, PARQUET_MAGIC_ENCRYPTED_FOOTER_CUBE};

pub type ParquetEncryptionKeyId = String;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParquetEncryptionKeyInfo {
    pub key_id: ParquetEncryptionKeyId,
    pub key: ParquetEncryptionKey,
}

/// Tells what mode (and also the key value(s)) a file is to be encrypted in (when writing) or is
/// permitted to be encrypted in (when reading).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ParquetEncryptionMode {
    /// Means the file is unencrypted
    Unencrypted,
    /// Means the file is footer-encrypted -- well, fully-encrypted.  The same key is used for all
    /// the columns too, in this implementation.
    FooterEncrypted(ParquetEncryptionKeyInfo),
}

/// Describes general parquet encryption configuration -- new files are encrypted with the
/// write_key(), but old files can be decrypted with any of the valid read keys.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParquetEncryptionConfig {
    // The last mode is the write mode (i.e. it has the write key), and all the prior modes are
    // valid read modes (i.e. valid read keys, or Unencrypted mode, if a user turned on encryption
    // but hasn't key-rotated unencrypted files away yet).
    keys: Vec<ParquetEncryptionMode>,
}

impl ParquetEncryptionConfig {
    pub fn new(keys: Vec<ParquetEncryptionMode>) -> Option<ParquetEncryptionConfig> {
        if keys.is_empty() {
            None
        } else {
            Some(ParquetEncryptionConfig { keys })
        }
    }

    pub fn write_key(&self) -> &ParquetEncryptionMode {
        self.keys.last().unwrap()
    }

    pub fn read_keys(&self) -> &[ParquetEncryptionMode] {
        self.keys.as_slice()
    }
}

// Since keys are 32 bytes (being 256 bits), we use 28-byte hashes to avoid mistaking a key for a
// key hash.
pub const PARQUET_KEY_HASH_LENGTH: usize = 28;
pub const PARQUET_KEY_SIZE: usize = 32; // Aes256Gcm, hence 32 bytes

/// Describes how we encrypt or encrypted the Parquet files.  Right now (in this implementation)
/// files can only be encrypted in "encrypted footer mode" with the footer and columns all encrypted
/// with the same key.

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct ParquetEncryptionKey {
    /// The key we use for all parts and components of the Parquet files.
    pub key: [u8; PARQUET_KEY_SIZE],
}

impl ParquetEncryptionKey {
    pub fn default() -> ParquetEncryptionKey {
        ParquetEncryptionKey {
            key: Default::default(),
        }
    }

    pub fn key_size() -> usize {
        Aes256Gcm::key_size()
    }

    pub fn generate_key() -> ParquetEncryptionKey {
        let key = Aes256Gcm::generate_key(OsRng);
        let mut result = ParquetEncryptionKey::default();
        result.key.copy_from_slice(&key);
        result
    }

    pub fn to_aes256_gcm_key(&self) -> aes_gcm::Key<Aes256Gcm> {
        let mut result = aes_gcm::Key::<Aes256Gcm>::default();
        let r: &mut [u8] = &mut result;
        r.copy_from_slice(&self.key);
        result
    }

    pub fn compute_key_hash(&self) -> [u8; PARQUET_KEY_HASH_LENGTH] {
        let mut hasher = Sha3_224::new();
        hasher.update(&self.key);
        let result = hasher.finalize();
        result.into()
    }
}

pub const AAD_FILE_UNIQUE_SIZE: usize = 20;
pub type RandomFileIdentifier = [u8; AAD_FILE_UNIQUE_SIZE];

const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
/// The value is 32.  A 4-byte length field, 12-byte nonce, 16-byte tag.
pub const USUAL_ENCRYPTION_OVERHEAD: usize = 4 + NONCE_SIZE + TAG_SIZE;

pub fn generate_random_file_identifier() -> RandomFileIdentifier {
    let mut v = [0u8; AAD_FILE_UNIQUE_SIZE];
    OsRng.fill_bytes(&mut v);
    v
}

/// Returns the magic to use at the beginning and end of the file (depending on whether we use footer encryption)
pub fn parquet_magic(is_footer_encrypted: bool) -> [u8; 4] {
    // For now ParquetEncryptionKey only allows footer encryption mode.  And we use a custom "PARC"
    // magic until we have checked that we're exactly following the format spec defined with "PARE".
    if !is_footer_encrypted {
        PARQUET_MAGIC
    } else {
        PARQUET_MAGIC_ENCRYPTED_FOOTER_CUBE
    }
}

// TODO: Could return fixed length array or some flat array,size pair instead of allocating.
pub fn parquet_aad_suffix(
    file_identifier: &RandomFileIdentifier,
    aad_module_type: u8,
    row_group_ordinal: i16,
    column_ordinal: u16,
    page_ordinal: Option<u16>,
) -> Vec<u8> {
    let mut aad = Vec::<u8>::new();
    aad.extend_from_slice(file_identifier);
    aad.push(aad_module_type);
    let _ = aad.write_i16::<LittleEndian>(row_group_ordinal);
    let _ = aad.write_u16::<LittleEndian>(column_ordinal);
    if let Some(page_ordinal) = page_ordinal {
        let _ = aad.write_u16::<LittleEndian>(page_ordinal);
    }
    aad
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

        let written_len = u32::try_from(buflen - 4 + TAG_SIZE).map_err(|_| {
            general_err!("Error encrypting {}.  Module is too large", what)
        })?;
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

pub fn decrypt_module<R: Read>(
    what: &str,
    mut r: R,
    encryption_key: &ParquetEncryptionKey,
    aad: &[u8],
) -> Result<Cursor<Vec<u8>>> {
    let mut cipher = Aes256Gcm::new(&encryption_key.to_aes256_gcm_key());

    let buflen = r.read_u32::<LittleEndian>()?;
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
        .decrypt_in_place_detached(
            &nonce,
            aad,
            &mut buf[NONCE_SIZE..buflen - TAG_SIZE],
            &tag,
        )
        .map_err(|_| general_err!("Error decrypting {}", what))?;

    // Now trim the buf of its trailing tag, and return a Cursor that skips past the nonce.
    // And just to prevent any weirdness, zero out the nonce.
    buf.truncate(buflen - TAG_SIZE);
    buf[..NONCE_SIZE].fill(0);

    let mut cursor = Cursor::new(buf);
    cursor.set_position(NONCE_SIZE as u64);

    Ok(cursor)
}
