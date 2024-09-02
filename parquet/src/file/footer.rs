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

use std::{
    cmp::min,
    io::{Cursor, Read, Seek, SeekFrom},
    sync::Arc,
};

use byteorder::{ByteOrder, LittleEndian};
use parquet_format::{ColumnOrder as TColumnOrder, FileCryptoMetaData as TFileCryptoMetaData, FileMetaData as TFileMetaData};
use thrift::protocol::TCompactInputProtocol;

use crate::basic::ColumnOrder;

use crate::errors::{ParquetError, Result};
use crate::file::{
    metadata::*, reader::ChunkReader, DEFAULT_FOOTER_READ_SIZE, FOOTER_SIZE,
    PARQUET_MAGIC,
};

use crate::schema::types::{self, SchemaDescriptor};

use crate::file::{encryption::{decrypt_module, parquet_magic, ParquetEncryptionConfig, PARQUET_KEY_HASH_LENGTH, ParquetEncryptionKey, ParquetEncryptionKeyInfo, RandomFileIdentifier, AAD_FILE_UNIQUE_SIZE}, PARQUET_MAGIC_ENCRYPTED_FOOTER_CUBE, PARQUET_MAGIC_UNSUPPORTED_PARE};

fn select_key(encryption_config: &ParquetEncryptionConfig, key_metadata: &Option<Vec<u8>>) -> Result<ParquetEncryptionKey> {
    if let Some(key_id) = key_metadata {
         if key_id.len() != PARQUET_KEY_HASH_LENGTH {
            return Err(general_err!("Unsupported Parquet file.  key_metadata field length is not supported"));
         }
         let mut key_id_arr = [0u8; PARQUET_KEY_HASH_LENGTH];
         key_id_arr.copy_from_slice(&key_id);
         let read_keys: &[ParquetEncryptionKeyInfo] = encryption_config.read_keys();
         for key_info in read_keys {
            if key_info.key.compute_key_hash() == key_id_arr {
                return Ok(key_info.key)
            }
         }
         return Err(general_err!("Parquet file is encrypted with an unknown or out-of-rotation key"));
    } else {
        return Err(general_err!("Unsupported Parquet file.  Expecting key_metadata field to be used"));
    }
}

/// Layout of Parquet file
/// +---------------------------+-----+---+
/// |      Rest of file         |  B  | A |
/// +---------------------------+-----+---+
/// where A: parquet footer, B: parquet metadata.
///
/// The reader first reads DEFAULT_FOOTER_SIZE bytes from the end of the file.
/// If it is not enough according to the length indicated in the footer, it reads more bytes.
pub fn parse_metadata<R: ChunkReader>(chunk_reader: &R, encryption_config: &Option<ParquetEncryptionConfig>) -> Result<(ParquetMetaData, Option<ParquetEncryptionKey>)> {
    // check file is large enough to hold footer
    let file_size = chunk_reader.len();
    if file_size < (FOOTER_SIZE as u64) {
        return Err(general_err!(
            "Invalid Parquet file. Size is smaller than footer"
        ));
    }

    // read and cache up to DEFAULT_FOOTER_READ_SIZE bytes from the end and process the footer
    let default_end_len = min(DEFAULT_FOOTER_READ_SIZE, chunk_reader.len() as usize);
    let mut default_end_reader = chunk_reader
        .get_read(chunk_reader.len() - default_end_len as u64, default_end_len)?;
    let mut default_len_end_buf = vec![0; default_end_len];
    default_end_reader.read_exact(&mut default_len_end_buf)?;

    // check this is indeed a parquet file
    {
        let trailing_magic: &[u8] = &default_len_end_buf[default_end_len - 4..];
        if trailing_magic != parquet_magic(encryption_config.is_some()) {
            if trailing_magic == PARQUET_MAGIC {
                return Err(general_err!("Invalid Parquet file in encrypted mode.  File (or at least the Parquet footer) is not encrypted"));
            } else if trailing_magic == PARQUET_MAGIC_ENCRYPTED_FOOTER_CUBE {
                return Err(general_err!("Invalid Parquet file in unencrypted mode.  File is encrypted"));
            } else if trailing_magic == PARQUET_MAGIC_UNSUPPORTED_PARE {
                return Err(general_err!("Unsupported Parquet file.  File is encrypted with the standard PARE encryption format"));
            } else {
                return Err(general_err!("Invalid Parquet file. Corrupt footer"));
            }
        }
    }

    // get the metadata length from the footer
    let metadata_len = LittleEndian::read_i32(
        &default_len_end_buf[default_end_len - 8..default_end_len - 4],
    ) as i64;
    if metadata_len < 0 {
        return Err(general_err!(
            "Invalid Parquet file. Metadata length is less than zero ({})",
            metadata_len
        ));
    }
    let footer_metadata_len = FOOTER_SIZE + metadata_len as usize;

    // build up the reader covering the entire metadata (but _not_ the last 8 bytes of
    // [metadata_len, magic])
    default_len_end_buf.truncate(default_len_end_buf.len() - FOOTER_SIZE);
    let mut default_end_cursor = Cursor::new(default_len_end_buf);

    let mut metadata_read: Box<dyn Read>;
    if footer_metadata_len > file_size as usize {
        return Err(general_err!(
            "Invalid Parquet file. Metadata start is less than zero ({})",
            file_size as i64 - footer_metadata_len as i64
        ));
    } else if footer_metadata_len < DEFAULT_FOOTER_READ_SIZE {
        // the whole metadata is in the bytes we already read
        default_end_cursor.seek(SeekFrom::End(-(metadata_len as i64)))?;
        metadata_read = Box::new(default_end_cursor);
    } else {
        // the end of file read by default is not long enough, read missing bytes
        let complementary_end_read = chunk_reader.get_read(
            file_size - footer_metadata_len as u64,
            footer_metadata_len - default_end_len,
        )?;
        metadata_read = Box::new(complementary_end_read.chain(default_end_cursor));
    }

    let returned_encryption_key: Option<ParquetEncryptionKey>;

    let random_file_identifier: Option<RandomFileIdentifier>;
    if let Some(encryption_config) = encryption_config {
        let file_crypto_metadata = {
            let mut prot = TCompactInputProtocol::new(&mut metadata_read);
            TFileCryptoMetaData::read_from_in_protocol(&mut prot)
            .map_err(|e| ParquetError::General(format!("Could not parse crypto metadata: {}", e)))?
        };

        let encryption_key = select_key(encryption_config, &file_crypto_metadata.key_metadata)?;

        let mut aad_file_unique: RandomFileIdentifier;
        // TODO: What's to stop somebody from switching out aad_file_unique with their own value and then swapping components between files?
        match file_crypto_metadata.encryption_algorithm {
            parquet_format::EncryptionAlgorithm::AESGCMV1(gcmv1) => {
                if gcmv1.aad_prefix.is_some() || gcmv1.supply_aad_prefix.is_some() {
                    return Err(general_err!("Unsupported Parquet file. Use of aad_prefix is not expected"));
                }
                if let Some(afu) = gcmv1.aad_file_unique {
                    if afu.len() != AAD_FILE_UNIQUE_SIZE {
                        return Err(general_err!("Unsupported Parquet file. aad_file_unique is not of the expected size"));
                    }
                    aad_file_unique = [0u8; AAD_FILE_UNIQUE_SIZE];
                    aad_file_unique.copy_from_slice(&afu);
                } else {
                    return Err(general_err!("Unsupported Parquet file. aad_file_unique must be set"));
                }
            },
            parquet_format::EncryptionAlgorithm::AESGCMCTRV1(_) => {
                return Err(general_err!("Unsupported Parquet file. AES_GCM_CTR_V1 mode is not expected"));
            }
        }

        let no_aad = &[];
        let plaintext_cursor = decrypt_module("footer", metadata_read, &encryption_key, no_aad)?;

        metadata_read = Box::new(plaintext_cursor);

        returned_encryption_key = Some(encryption_key);
        random_file_identifier = Some(aad_file_unique);
    } else {
        returned_encryption_key = None;
        random_file_identifier = None;
    }

    // TODO: row group filtering
    let mut prot = TCompactInputProtocol::new(metadata_read);
    let t_file_metadata: TFileMetaData = TFileMetaData::read_from_in_protocol(&mut prot)
        .map_err(|e| ParquetError::General(format!("Could not parse metadata: {}", e)))?;
    if t_file_metadata.encryption_algorithm.is_some() || t_file_metadata.footer_signing_key_metadata.is_some() {
        return Err(general_err!("Unsupported Parquet file. Plaintext footer mode is not supported"));
    }

    let schema = types::from_thrift(&t_file_metadata.schema)?;
    let schema_descr = Arc::new(SchemaDescriptor::new(schema));
    let mut row_groups = Vec::new();
    for rg in t_file_metadata.row_groups {
        row_groups.push(RowGroupMetaData::from_thrift(schema_descr.clone(), rg)?);
    }
    let column_orders = parse_column_orders(t_file_metadata.column_orders, &schema_descr);

    let file_metadata = FileMetaData::new(
        t_file_metadata.version,
        t_file_metadata.num_rows,
        t_file_metadata.created_by,
        t_file_metadata.key_value_metadata,
        schema_descr,
        column_orders,
        random_file_identifier,
    );
    Ok((ParquetMetaData::new_with_size(
        file_metadata,
        row_groups,
        footer_metadata_len as u32,
    ), returned_encryption_key))
}

/// Parses column orders from Thrift definition.
/// If no column orders are defined, returns `None`.
fn parse_column_orders(
    t_column_orders: Option<Vec<TColumnOrder>>,
    schema_descr: &SchemaDescriptor,
) -> Option<Vec<ColumnOrder>> {
    match t_column_orders {
        Some(orders) => {
            // Should always be the case
            assert_eq!(
                orders.len(),
                schema_descr.num_columns(),
                "Column order length mismatch"
            );
            let mut res = Vec::new();
            for (i, column) in schema_descr.columns().iter().enumerate() {
                match orders[i] {
                    TColumnOrder::TYPEORDER(_) => {
                        let sort_order = ColumnOrder::get_sort_order(
                            column.logical_type(),
                            column.converted_type(),
                            column.physical_type(),
                        );
                        res.push(ColumnOrder::TYPE_DEFINED_ORDER(sort_order));
                    }
                }
            }
            Some(res)
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::basic::SortOrder;
    use crate::basic::Type;
    use crate::schema::types::Type as SchemaType;
    use crate::util::test_common::get_temp_file;
    use parquet_format::TypeDefinedOrder;

    #[test]
    fn test_parse_metadata_size_smaller_than_footer() {
        let test_file = get_temp_file("corrupt-1.parquet", &[]);
        let reader_result = parse_metadata(&test_file, &None);
        assert!(reader_result.is_err());
        assert_eq!(
            reader_result.err().unwrap(),
            general_err!("Invalid Parquet file. Size is smaller than footer")
        );
    }

    #[test]
    fn test_parse_metadata_corrupt_footer() {
        let test_file = get_temp_file("corrupt-2.parquet", &[1, 2, 3, 4, 5, 6, 7, 8]);
        let reader_result = parse_metadata(&test_file, &None);
        assert!(reader_result.is_err());
        assert_eq!(
            reader_result.err().unwrap(),
            general_err!("Invalid Parquet file. Corrupt footer")
        );
    }

    #[test]
    fn test_parse_metadata_invalid_length() {
        let test_file =
            get_temp_file("corrupt-3.parquet", &[0, 0, 0, 255, b'P', b'A', b'R', b'1']);
        let reader_result = parse_metadata(&test_file, &None);
        assert!(reader_result.is_err());
        assert_eq!(
            reader_result.err().unwrap(),
            general_err!(
                "Invalid Parquet file. Metadata length is less than zero (-16777216)"
            )
        );
    }

    #[test]
    fn test_parse_metadata_invalid_start() {
        let test_file =
            get_temp_file("corrupt-4.parquet", &[255, 0, 0, 0, b'P', b'A', b'R', b'1']);
        let reader_result = parse_metadata(&test_file, &None);
        assert!(reader_result.is_err());
        assert_eq!(
            reader_result.err().unwrap(),
            general_err!("Invalid Parquet file. Metadata start is less than zero (-255)")
        );
    }

    #[test]
    fn test_metadata_column_orders_parse() {
        // Define simple schema, we do not need to provide logical types.
        let mut fields = vec![
            Arc::new(
                SchemaType::primitive_type_builder("col1", Type::INT32)
                    .build()
                    .unwrap(),
            ),
            Arc::new(
                SchemaType::primitive_type_builder("col2", Type::FLOAT)
                    .build()
                    .unwrap(),
            ),
        ];
        let schema = SchemaType::group_type_builder("schema")
            .with_fields(&mut fields)
            .build()
            .unwrap();
        let schema_descr = SchemaDescriptor::new(Arc::new(schema));

        let t_column_orders = Some(vec![
            TColumnOrder::TYPEORDER(TypeDefinedOrder::new()),
            TColumnOrder::TYPEORDER(TypeDefinedOrder::new()),
        ]);

        assert_eq!(
            parse_column_orders(t_column_orders, &schema_descr),
            Some(vec![
                ColumnOrder::TYPE_DEFINED_ORDER(SortOrder::SIGNED),
                ColumnOrder::TYPE_DEFINED_ORDER(SortOrder::SIGNED)
            ])
        );

        // Test when no column orders are defined.
        assert_eq!(parse_column_orders(None, &schema_descr), None);
    }

    #[test]
    #[should_panic(expected = "Column order length mismatch")]
    fn test_metadata_column_orders_len_mismatch() {
        let schema = SchemaType::group_type_builder("schema").build().unwrap();
        let schema_descr = SchemaDescriptor::new(Arc::new(schema));

        let t_column_orders =
            Some(vec![TColumnOrder::TYPEORDER(TypeDefinedOrder::new())]);

        parse_column_orders(t_column_orders, &schema_descr);
    }
}
