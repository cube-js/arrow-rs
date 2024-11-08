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

//! Contains file writer API, and provides methods to write row groups and columns by
//! using row group writers and column writers respectively.

use std::{
    convert::TryFrom,
    io::{Seek, SeekFrom, Write},
    sync::Arc,
};

use byteorder::{ByteOrder, LittleEndian};
use parquet_format as parquet;
use thrift::protocol::{TCompactOutputProtocol, TOutputProtocol};

use crate::basic::PageType;
use crate::column::{
    page::{CompressedPage, Page, PageWriteSpec, PageWriter},
    writer::{get_column_writer, ColumnWriter},
};
use crate::errors::{ParquetError, Result};
use crate::file::{
    metadata::*, properties::WriterPropertiesPtr,
    statistics::to_thrift as statistics_to_thrift, FOOTER_SIZE,
};
use crate::schema::types::{self, SchemaDescPtr, SchemaDescriptor, TypePtr};
use crate::util::io::{FileSink, Position};

// Exposed publically so client code can implement [`ParquetWriter`]
pub use crate::util::io::TryClone;

// Exposed publically for convenience of writing Parquet to a buffer of bytes
pub use crate::util::cursor::InMemoryWriteableCursor;

use crate::file::{
    encryption::{
        encrypt_module, parquet_aad_suffix, parquet_magic, ParquetEncryptionKey,
        PrepaddedPlaintext, RandomFileIdentifier, USUAL_ENCRYPTION_OVERHEAD,
    },
    serialized_reader::{
        COLUMNCHUNK_MODULE_TYPE, DATA_PAGE_HEADER_MODULE_TYPE, DATA_PAGE_MODULE_TYPE,
        DICTIONARY_PAGE_HEADER_MODULE_TYPE, DICTIONARY_PAGE_MODULE_TYPE,
    },
};

// ----------------------------------------------------------------------
// APIs for file & row group writers

/// Parquet file writer API.
/// Provides methods to write row groups sequentially.
///
/// The main workflow should be as following:
/// - Create file writer, this will open a new file and potentially write some metadata.
/// - Request a new row group writer by calling `next_row_group`.
/// - Once finished writing row group, close row group writer by passing it into
/// `close_row_group` method - this will finalise row group metadata and update metrics.
/// - Write subsequent row groups, if necessary.
/// - After all row groups have been written, close the file writer using `close` method.
pub trait FileWriter {
    /// Creates new row group from this file writer.
    /// In case of IO error or Thrift error, returns `Err`.
    ///
    /// There is no limit on a number of row groups in a file; however, row groups have
    /// to be written sequentially. Every time the next row group is requested, the
    /// previous row group must be finalised and closed using `close_row_group` method.
    fn next_row_group(&mut self) -> Result<Box<dyn RowGroupWriter>>;

    /// Finalises and closes row group that was created using `next_row_group` method.
    /// After calling this method, the next row group is available for writes.
    fn close_row_group(
        &mut self,
        row_group_writer: Box<dyn RowGroupWriter>,
    ) -> Result<()>;

    /// Closes and finalises file writer, returning the file metadata.
    ///
    /// All row groups must be appended before this method is called.
    /// No writes are allowed after this point.
    ///
    /// Can be called multiple times. It is up to implementation to either result in
    /// no-op, or return an `Err` for subsequent calls.
    fn close(&mut self) -> Result<parquet::FileMetaData>;
}

/// Parquet row group writer API.
/// Provides methods to access column writers in an iterator-like fashion, order is
/// guaranteed to match the order of schema leaves (column descriptors).
///
/// All columns should be written sequentially; the main workflow is:
/// - Request the next column using `next_column` method - this will return `None` if no
/// more columns are available to write.
/// - Once done writing a column, close column writer with `close_column` method - this
/// will finalise column chunk metadata and update row group metrics.
/// - Once all columns have been written, close row group writer with `close` method -
/// it will return row group metadata and is no-op on already closed row group.
pub trait RowGroupWriter {
    /// Returns the next column writer, if available; otherwise returns `None`.
    /// In case of any IO error or Thrift error, or if row group writer has already been
    /// closed returns `Err`.
    ///
    /// To request the next column writer, the previous one must be finalised and closed
    /// using `close_column`.
    fn next_column(&mut self) -> Result<Option<ColumnWriter>>;

    /// Closes column writer that was created using `next_column` method.
    /// This should be called before requesting the next column writer.
    fn close_column(&mut self, column_writer: ColumnWriter) -> Result<()>;

    /// Closes this row group writer and returns row group metadata.
    /// After calling this method row group writer must not be used.
    ///
    /// It is recommended to call this method before requesting another row group, but it
    /// will be closed automatically before returning a new row group.
    ///
    /// Can be called multiple times. In subsequent calls will result in no-op and return
    /// already created row group metadata.
    fn close(&mut self) -> Result<RowGroupMetaDataPtr>;
}

// ----------------------------------------------------------------------
// Serialized impl for file & row group writers

pub trait ParquetWriter: Write + Seek + TryClone {}
impl<T: Write + Seek + TryClone> ParquetWriter for T {}

/// A serialized implementation for Parquet [`FileWriter`].
/// See documentation on file writer for more information.
pub struct SerializedFileWriter<W: ParquetWriter> {
    buf: W,
    schema: TypePtr,
    descr: SchemaDescPtr,
    props: WriterPropertiesPtr,
    total_num_rows: i64,
    row_groups: Vec<RowGroupMetaDataPtr>,
    previous_writer_closed: bool,
    is_closed: bool,
}

impl<W: ParquetWriter> SerializedFileWriter<W> {
    /// Creates new file writer.
    pub fn new(
        mut buf: W,
        schema: TypePtr,
        properties: WriterPropertiesPtr,
    ) -> Result<Self> {
        Self::start_file(&mut buf, properties.encryption_info.is_some())?;
        Ok(Self {
            buf,
            schema: schema.clone(),
            descr: Arc::new(SchemaDescriptor::new(schema)),
            props: properties,
            total_num_rows: 0,
            row_groups: Vec::new(),
            previous_writer_closed: true,
            is_closed: false,
        })
    }

    /// Writes magic bytes at the beginning of the file, depending on whether the file is encrypted
    /// (in encrypted footer mode).
    fn start_file(buf: &mut W, is_footer_encrypted: bool) -> Result<()> {
        buf.write_all(&parquet_magic(is_footer_encrypted))?;
        Ok(())
    }

    /// Finalises active row group writer, otherwise no-op.
    fn finalise_row_group_writer(
        &mut self,
        mut row_group_writer: Box<dyn RowGroupWriter>,
    ) -> Result<()> {
        let row_group_metadata = row_group_writer.close()?;
        self.total_num_rows += row_group_metadata.num_rows();
        self.row_groups.push(row_group_metadata);
        Ok(())
    }

    /// Assembles and writes metadata at the end of the file.
    fn write_metadata(&mut self) -> Result<parquet::FileMetaData> {
        let file_metadata = parquet::FileMetaData {
            version: self.props.writer_version().as_num(),
            schema: types::to_thrift(self.schema.as_ref())?,
            num_rows: self.total_num_rows as i64,
            row_groups: self
                .row_groups
                .as_slice()
                .iter()
                .map(|v| v.to_thrift())
                .collect(),
            key_value_metadata: self.props.key_value_metadata().to_owned(),
            created_by: Some(self.props.created_by().to_owned()),
            column_orders: None,
            // encryption_algorithm and footer_signing_key_metadata are used in plaintext footer
            // mode, which we don't use.
            encryption_algorithm: None,
            footer_signing_key_metadata: None,
        };

        // Write file metadata (FileCryptoMetaData (if applicable) and FileMetaData)
        let start_pos = self.buf.seek(SeekFrom::Current(0))?;

        if let Some((key_info, random_file_identifier)) = &self.props.encryption_info {
            // FileCryptoMetaData and FileMetadata

            let file_crypto_metadata = parquet::FileCryptoMetaData {
                encryption_algorithm: parquet::EncryptionAlgorithm::AESGCMV1(
                    parquet_format::AesGcmV1 {
                        aad_prefix: None,
                        aad_file_unique: Some(random_file_identifier.to_vec()),
                        supply_aad_prefix: None,
                    },
                ),
                // TODO: Maybe the user of this parquet lib will want to make their own decision
                // about this.  Right now this library supports passing multiple read keys, and uses
                // the Sha3-256 of the key as a key id to select the key.
                key_metadata: Some(key_info.key.compute_key_hash().to_vec()),
            };

            {
                let mut protocol = TCompactOutputProtocol::new(&mut self.buf);
                file_crypto_metadata.write_to_out_protocol(&mut protocol)?;
                protocol.flush()?;
            }

            let mut plaintext = PrepaddedPlaintext::new();
            {
                let mut protocol = TCompactOutputProtocol::new(plaintext.buf_mut());
                file_metadata.write_to_out_protocol(&mut protocol)?;
                protocol.flush()?;
            }

            let no_aad = &[];
            encrypt_module(
                "FileMetaData",
                &mut self.buf,
                &key_info.key,
                plaintext,
                no_aad,
            )?;
        } else {
            // just FileMetaData
            let mut protocol = TCompactOutputProtocol::new(&mut self.buf);
            file_metadata.write_to_out_protocol(&mut protocol)?;
            protocol.flush()?;
        }
        let end_pos = self.buf.seek(SeekFrom::Current(0))?;

        // Write footer
        let mut footer_buffer: [u8; FOOTER_SIZE] = [0; FOOTER_SIZE];
        let metadata_len = (end_pos - start_pos) as i32;
        LittleEndian::write_i32(&mut footer_buffer, metadata_len);
        (&mut footer_buffer[4..])
            .write_all(&parquet_magic(self.props.encryption_info.is_some()))?;
        self.buf.write_all(&footer_buffer)?;
        Ok(file_metadata)
    }

    #[inline]
    fn assert_closed(&self) -> Result<()> {
        if self.is_closed {
            Err(general_err!("File writer is closed"))
        } else {
            Ok(())
        }
    }

    #[inline]
    fn assert_previous_writer_closed(&self) -> Result<()> {
        if !self.previous_writer_closed {
            Err(general_err!("Previous row group writer was not closed"))
        } else {
            Ok(())
        }
    }
}

impl<W: 'static + ParquetWriter> FileWriter for SerializedFileWriter<W> {
    #[inline]
    fn next_row_group(&mut self) -> Result<Box<dyn RowGroupWriter>> {
        self.assert_closed()?;
        self.assert_previous_writer_closed()?;
        let row_group_ordinal: i16 =
            i16::try_from(self.row_groups.len()).map_err(|_| {
                general_err!("Number of row groups cannot exceed {}", i16::MAX as i32 + 1)
            })?;
        let row_group_writer = SerializedRowGroupWriter::new(
            self.descr.clone(),
            self.props.clone(),
            row_group_ordinal,
            &self.buf,
        );
        self.previous_writer_closed = false;
        Ok(Box::new(row_group_writer))
    }

    #[inline]
    fn close_row_group(
        &mut self,
        row_group_writer: Box<dyn RowGroupWriter>,
    ) -> Result<()> {
        self.assert_closed()?;
        let res = self.finalise_row_group_writer(row_group_writer);
        self.previous_writer_closed = res.is_ok();
        res
    }

    #[inline]
    fn close(&mut self) -> Result<parquet::FileMetaData> {
        self.assert_closed()?;
        self.assert_previous_writer_closed()?;
        let metadata = self.write_metadata()?;
        self.buf.flush()?;
        self.is_closed = true;
        Ok(metadata)
    }
}

/// A serialized implementation for Parquet [`RowGroupWriter`].
/// Coordinates writing of a row group with column writers.
/// See documentation on row group writer for more information.
pub struct SerializedRowGroupWriter<W: ParquetWriter> {
    descr: SchemaDescPtr,
    props: WriterPropertiesPtr,
    buf: W,
    total_rows_written: Option<u64>,
    total_bytes_written: u64,
    column_index: usize,
    previous_writer_closed: bool,
    row_group_ordinal: i16,
    row_group_metadata: Option<RowGroupMetaDataPtr>,
    column_chunks: Vec<ColumnChunkMetaData>,
}

impl<W: 'static + ParquetWriter> SerializedRowGroupWriter<W> {
    pub fn new(
        schema_descr: SchemaDescPtr,
        properties: WriterPropertiesPtr,
        row_group_ordinal: i16,
        buf: &W,
    ) -> Self {
        let num_columns = schema_descr.num_columns();
        Self {
            descr: schema_descr,
            props: properties,
            buf: buf.try_clone().unwrap(),
            total_rows_written: None,
            total_bytes_written: 0,
            column_index: 0,
            previous_writer_closed: true,
            row_group_ordinal,
            row_group_metadata: None,
            column_chunks: Vec::with_capacity(num_columns),
        }
    }

    /// Checks and finalises current column writer.
    fn finalise_column_writer(&mut self, writer: ColumnWriter) -> Result<()> {
        let (bytes_written, rows_written, metadata) = match writer {
            ColumnWriter::BoolColumnWriter(typed) => typed.close()?,
            ColumnWriter::Int32ColumnWriter(typed) => typed.close()?,
            ColumnWriter::Int64ColumnWriter(typed) => typed.close()?,
            ColumnWriter::Int96ColumnWriter(typed) => typed.close()?,
            ColumnWriter::FloatColumnWriter(typed) => typed.close()?,
            ColumnWriter::DoubleColumnWriter(typed) => typed.close()?,
            ColumnWriter::ByteArrayColumnWriter(typed) => typed.close()?,
            ColumnWriter::FixedLenByteArrayColumnWriter(typed) => typed.close()?,
        };

        // Update row group writer metrics
        self.total_bytes_written += bytes_written;
        self.column_chunks.push(metadata);
        if let Some(rows) = self.total_rows_written {
            if rows != rows_written {
                return Err(general_err!(
                    "Incorrect number of rows, expected {} != {} rows",
                    rows,
                    rows_written
                ));
            }
        } else {
            self.total_rows_written = Some(rows_written);
        }

        Ok(())
    }

    #[inline]
    fn assert_closed(&self) -> Result<()> {
        if self.row_group_metadata.is_some() {
            Err(general_err!("Row group writer is closed"))
        } else {
            Ok(())
        }
    }

    #[inline]
    fn assert_previous_writer_closed(&self) -> Result<()> {
        if !self.previous_writer_closed {
            Err(general_err!("Previous column writer was not closed"))
        } else {
            Ok(())
        }
    }
}

impl<W: 'static + ParquetWriter> RowGroupWriter for SerializedRowGroupWriter<W> {
    #[inline]
    fn next_column(&mut self) -> Result<Option<ColumnWriter>> {
        self.assert_closed()?;
        self.assert_previous_writer_closed()?;

        if self.column_index >= self.descr.num_columns() {
            return Ok(None);
        }
        let column_ordinal: u16 = u16::try_from(self.column_index).map_err(|_| {
            general_err!("Number of columns cannot exceed {}", u16::MAX as u32 + 1)
        })?;
        let sink = FileSink::new(&self.buf);
        let page_writer = Box::new(SerializedPageWriter::new(
            sink,
            self.props
                .encryption_info
                .as_ref()
                .map(|(key_info, rfi)| (key_info.key, *rfi)),
            self.row_group_ordinal,
            column_ordinal,
        ));
        let column_writer = get_column_writer(
            self.descr.column(self.column_index),
            self.props.clone(),
            page_writer,
        );
        self.column_index += 1;
        self.previous_writer_closed = false;

        Ok(Some(column_writer))
    }

    #[inline]
    fn close_column(&mut self, column_writer: ColumnWriter) -> Result<()> {
        let res = self.finalise_column_writer(column_writer);
        self.previous_writer_closed = res.is_ok();
        res
    }

    #[inline]
    fn close(&mut self) -> Result<RowGroupMetaDataPtr> {
        if self.row_group_metadata.is_none() {
            self.assert_previous_writer_closed()?;

            let column_chunks = std::mem::take(&mut self.column_chunks);
            let row_group_metadata =
                RowGroupMetaData::builder(self.descr.clone(), self.row_group_ordinal)
                    .set_column_metadata(column_chunks)
                    .set_total_byte_size(self.total_bytes_written as i64)
                    .set_num_rows(self.total_rows_written.unwrap_or(0) as i64)
                    .build()?;

            self.row_group_metadata = Some(Arc::new(row_group_metadata));
        }

        let metadata = self.row_group_metadata.as_ref().unwrap().clone();
        Ok(metadata)
    }
}

/// A serialized implementation for Parquet [`PageWriter`].
/// Writes and serializes pages and metadata into output stream.
///
/// `SerializedPageWriter` should not be used after calling `close()`.
pub struct SerializedPageWriter<T: Write + Position> {
    sink: T,
    encryption_info: Option<(ParquetEncryptionKey, RandomFileIdentifier)>,
    row_group_ordinal: i16,
    column_ordinal: u16,
}

impl<T: Write + Position> SerializedPageWriter<T> {
    /// Creates new page writer.
    pub fn new(
        sink: T,
        encryption_info: Option<(ParquetEncryptionKey, RandomFileIdentifier)>,
        row_group_ordinal: i16,
        column_ordinal: u16,
    ) -> Self {
        Self {
            sink,
            encryption_info,
            row_group_ordinal,
            column_ordinal,
        }
    }

    /// Serializes page header into Thrift.
    /// aad_header_module_type needs to be the correct value that corresponds to header.page_type().
    /// Returns number of bytes that have been written into the sink.
    #[inline]
    fn serialize_page_header(
        &mut self,
        header: parquet::PageHeader,
        aad_header_module_type: u8,
        page_ordinal: Option<u16>,
    ) -> Result<usize> {
        let start_pos = self.sink.pos();
        if let Some((encryption_key, random_file_identifier)) = &self.encryption_info {
            let aad_suffix = parquet_aad_suffix(
                random_file_identifier,
                aad_header_module_type,
                self.row_group_ordinal,
                self.column_ordinal,
                page_ordinal,
            );

            let mut plaintext = PrepaddedPlaintext::new();
            {
                let mut protocol = TCompactOutputProtocol::new(plaintext.buf_mut());
                header.write_to_out_protocol(&mut protocol)?;
                protocol.flush()?;
            }

            encrypt_module(
                "PageHeader",
                &mut self.sink,
                encryption_key,
                plaintext,
                &aad_suffix,
            )?;
        } else {
            let mut protocol = TCompactOutputProtocol::new(&mut self.sink);
            header.write_to_out_protocol(&mut protocol)?;
            protocol.flush()?;
        }
        Ok((self.sink.pos() - start_pos) as usize)
    }

    /// Serializes column chunk into Thrift.
    /// Returns Ok() if there are not errors serializing and writing data into the sink.
    #[inline]
    fn serialize_column_chunk(&mut self, chunk: parquet::ColumnChunk) -> Result<()> {
        if let Some((encryption_key, random_file_identifier)) = &self.encryption_info {
            // TODO: Verify that we behave the same way as other arrow implementations here, in the
            // sense that we should verify that others write out this ColumnChunk _here_ at all.
            let aad_module_type = COLUMNCHUNK_MODULE_TYPE;
            let aad_suffix = parquet_aad_suffix(
                random_file_identifier,
                aad_module_type,
                self.row_group_ordinal,
                self.column_ordinal,
                None,
            );

            let mut plaintext = PrepaddedPlaintext::new();
            {
                let mut protocol = TCompactOutputProtocol::new(plaintext.buf_mut());
                chunk.write_to_out_protocol(&mut protocol)?;
                protocol.flush()?;
            }

            encrypt_module(
                "ColumnChunk",
                &mut self.sink,
                encryption_key,
                plaintext,
                &aad_suffix,
            )?;
        } else {
            let mut protocol = TCompactOutputProtocol::new(&mut self.sink);
            chunk.write_to_out_protocol(&mut protocol)?;
            protocol.flush()?;
        }
        Ok(())
    }
}

impl<T: Write + Position> PageWriter for SerializedPageWriter<T> {
    fn write_page(
        &mut self,
        page: CompressedPage,
        aad_page_ordinal: Option<u16>,
    ) -> Result<PageWriteSpec> {
        let uncompressed_size = page.uncompressed_size();
        let compressed_unencrypted_size = page.compressed_unencrypted_size();
        let compressed_size = (if self.encryption_info.is_some() {
            USUAL_ENCRYPTION_OVERHEAD
        } else {
            0
        }) + compressed_unencrypted_size;
        let num_values = page.num_values();
        let encoding = page.encoding();
        let page_type = page.page_type();

        let mut page_header = parquet::PageHeader {
            type_: page_type.into(),
            uncompressed_page_size: uncompressed_size as i32,
            compressed_page_size: compressed_size as i32,
            // TODO: Add support for crc checksum
            crc: None,
            data_page_header: None,
            index_page_header: None,
            dictionary_page_header: None,
            data_page_header_v2: None,
        };

        let aad_module_type: u8;
        let aad_header_module_type: u8;
        match *page.compressed_page() {
            Page::DataPage {
                def_level_encoding,
                rep_level_encoding,
                ref statistics,
                ..
            } => {
                let data_page_header = parquet::DataPageHeader {
                    num_values: num_values as i32,
                    encoding: encoding.into(),
                    definition_level_encoding: def_level_encoding.into(),
                    repetition_level_encoding: rep_level_encoding.into(),
                    statistics: statistics_to_thrift(statistics.as_ref()),
                };
                page_header.data_page_header = Some(data_page_header);
                aad_module_type = DATA_PAGE_MODULE_TYPE;
                aad_header_module_type = DATA_PAGE_HEADER_MODULE_TYPE;
            }
            Page::DataPageV2 {
                num_nulls,
                num_rows,
                def_levels_byte_len,
                rep_levels_byte_len,
                is_compressed,
                ref statistics,
                ..
            } => {
                let data_page_header_v2 = parquet::DataPageHeaderV2 {
                    num_values: num_values as i32,
                    num_nulls: num_nulls as i32,
                    num_rows: num_rows as i32,
                    encoding: encoding.into(),
                    definition_levels_byte_length: def_levels_byte_len as i32,
                    repetition_levels_byte_length: rep_levels_byte_len as i32,
                    is_compressed: Some(is_compressed),
                    statistics: statistics_to_thrift(statistics.as_ref()),
                };
                page_header.data_page_header_v2 = Some(data_page_header_v2);
                aad_module_type = DATA_PAGE_MODULE_TYPE;
                aad_header_module_type = DATA_PAGE_HEADER_MODULE_TYPE;
            }
            Page::DictionaryPage { is_sorted, .. } => {
                let dictionary_page_header = parquet::DictionaryPageHeader {
                    num_values: num_values as i32,
                    encoding: encoding.into(),
                    is_sorted: Some(is_sorted),
                };
                page_header.dictionary_page_header = Some(dictionary_page_header);
                aad_module_type = DICTIONARY_PAGE_MODULE_TYPE;
                aad_header_module_type = DICTIONARY_PAGE_HEADER_MODULE_TYPE;
            }
        }

        let start_pos = self.sink.pos();

        // TODO: header_size is after encryption -- is that what we want?  What about for uncompressed_size?
        let header_size = self.serialize_page_header(
            page_header,
            aad_header_module_type,
            aad_page_ordinal,
        )?;

        if let Some((encryption_key, random_file_identifier)) = &self.encryption_info {
            let aad_suffix = parquet_aad_suffix(
                random_file_identifier,
                aad_module_type,
                self.row_group_ordinal,
                self.column_ordinal,
                aad_page_ordinal,
            );

            let mut plaintext = PrepaddedPlaintext::new();
            plaintext.buf_mut().extend_from_slice(page.data());
            encrypt_module(
                "Page data",
                &mut self.sink,
                encryption_key,
                plaintext,
                &aad_suffix,
            )?;
        } else {
            self.sink.write_all(page.data())?;
        }

        let mut spec = PageWriteSpec::new();
        spec.page_type = page_type;
        spec.uncompressed_size = uncompressed_size + header_size;
        spec.compressed_size = compressed_size + header_size;
        spec.offset = start_pos;
        spec.bytes_written = self.sink.pos() - start_pos;
        // Number of values is incremented for data pages only
        if page_type == PageType::DATA_PAGE || page_type == PageType::DATA_PAGE_V2 {
            spec.num_values = num_values;
        }

        Ok(spec)
    }

    fn write_metadata(&mut self, metadata: &ColumnChunkMetaData) -> Result<()> {
        self.serialize_column_chunk(metadata.to_thrift())
    }

    fn close(&mut self) -> Result<()> {
        self.sink.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "windows"))]
    use std::os::unix::fs::FileExt;
    #[cfg(target_os = "windows")]
    use std::os::windows::fs::FileExt;
    use std::{
        fs::File,
        io::{Cursor, SeekFrom},
    };

    use crate::basic::{Compression, Encoding, IntType, LogicalType, Repetition, Type};
    use crate::column::page::PageReader;
    use crate::compression::{create_codec, Codec};
    use crate::file::encryption::{
        generate_random_file_identifier, ParquetEncryptionConfig,
        ParquetEncryptionKeyInfo, ParquetEncryptionMode,
    };
    use crate::file::reader::Length;
    use crate::file::{
        properties::{WriterProperties, WriterVersion},
        reader::{FileReader, SerializedFileReader, SerializedPageReader},
        statistics::{from_thrift, to_thrift, Statistics},
    };
    use crate::file::{PARQUET_MAGIC, PARQUET_MAGIC_ENCRYPTED_FOOTER_CUBE};
    use crate::record::RowAccessor;
    use crate::util::{memory::ByteBufferPtr, test_common::get_temp_file};

    #[test]
    fn test_file_writer_error_after_close() {
        let file = get_temp_file("test_file_writer_error_after_close", &[]);
        let schema = Arc::new(types::Type::group_type_builder("schema").build().unwrap());
        let props = Arc::new(WriterProperties::builder().build());
        let mut writer = SerializedFileWriter::new(file, schema, props).unwrap();
        writer.close().unwrap();
        {
            let res = writer.next_row_group();
            assert!(res.is_err());
            if let Err(err) = res {
                assert_eq!(format!("{}", err), "Parquet error: File writer is closed");
            }
        }
        {
            let res = writer.close();
            assert!(res.is_err());
            if let Err(err) = res {
                assert_eq!(format!("{}", err), "Parquet error: File writer is closed");
            }
        }
    }

    #[test]
    fn test_row_group_writer_error_after_close() {
        let file = get_temp_file("test_file_writer_row_group_error_after_close", &[]);
        let schema = Arc::new(types::Type::group_type_builder("schema").build().unwrap());
        let props = Arc::new(WriterProperties::builder().build());
        let mut writer = SerializedFileWriter::new(file, schema, props).unwrap();
        let mut row_group_writer = writer.next_row_group().unwrap();
        row_group_writer.close().unwrap();

        let res = row_group_writer.next_column();
        assert!(res.is_err());
        if let Err(err) = res {
            assert_eq!(
                format!("{}", err),
                "Parquet error: Row group writer is closed"
            );
        }
    }

    #[test]
    fn test_row_group_writer_error_not_all_columns_written() {
        let file =
            get_temp_file("test_row_group_writer_error_not_all_columns_written", &[]);
        let schema = Arc::new(
            types::Type::group_type_builder("schema")
                .with_fields(&mut vec![Arc::new(
                    types::Type::primitive_type_builder("col1", Type::INT32)
                        .build()
                        .unwrap(),
                )])
                .build()
                .unwrap(),
        );
        let props = Arc::new(WriterProperties::builder().build());
        let mut writer = SerializedFileWriter::new(file, schema, props).unwrap();
        let mut row_group_writer = writer.next_row_group().unwrap();
        let res = row_group_writer.close();
        assert!(res.is_err());
        if let Err(err) = res {
            assert_eq!(
                format!("{}", err),
                "Parquet error: Column length mismatch: 1 != 0"
            );
        }
    }

    #[test]
    fn test_row_group_writer_num_records_mismatch() {
        let file = get_temp_file("test_row_group_writer_num_records_mismatch", &[]);
        let schema = Arc::new(
            types::Type::group_type_builder("schema")
                .with_fields(&mut vec![
                    Arc::new(
                        types::Type::primitive_type_builder("col1", Type::INT32)
                            .with_repetition(Repetition::REQUIRED)
                            .build()
                            .unwrap(),
                    ),
                    Arc::new(
                        types::Type::primitive_type_builder("col2", Type::INT32)
                            .with_repetition(Repetition::REQUIRED)
                            .build()
                            .unwrap(),
                    ),
                ])
                .build()
                .unwrap(),
        );
        let props = Arc::new(WriterProperties::builder().build());
        let mut writer = SerializedFileWriter::new(file, schema, props).unwrap();
        let mut row_group_writer = writer.next_row_group().unwrap();

        let mut col_writer = row_group_writer.next_column().unwrap().unwrap();
        if let ColumnWriter::Int32ColumnWriter(ref mut typed) = col_writer {
            typed.write_batch(&[1, 2, 3], None, None).unwrap();
        }
        row_group_writer.close_column(col_writer).unwrap();

        let mut col_writer = row_group_writer.next_column().unwrap().unwrap();
        if let ColumnWriter::Int32ColumnWriter(ref mut typed) = col_writer {
            typed.write_batch(&[1, 2], None, None).unwrap();
        }

        let res = row_group_writer.close_column(col_writer);
        assert!(res.is_err());
        if let Err(err) = res {
            assert_eq!(
                format!("{}", err),
                "Parquet error: Incorrect number of rows, expected 3 != 2 rows"
            );
        }
    }

    #[test]
    fn test_file_writer_empty_file() {
        let file = get_temp_file("test_file_writer_write_empty_file", &[]);

        let schema = Arc::new(
            types::Type::group_type_builder("schema")
                .with_fields(&mut vec![Arc::new(
                    types::Type::primitive_type_builder("col1", Type::INT32)
                        .build()
                        .unwrap(),
                )])
                .build()
                .unwrap(),
        );
        let props = Arc::new(WriterProperties::builder().build());
        let mut writer =
            SerializedFileWriter::new(file.try_clone().unwrap(), schema, props).unwrap();
        writer.close().unwrap();

        let reader = SerializedFileReader::new(file).unwrap();
        assert_eq!(reader.get_row_iter(None).unwrap().count(), 0);
    }

    #[test]
    fn test_file_writer_with_metadata() {
        let file = get_temp_file("test_file_writer_write_with_metadata", &[]);

        let schema = Arc::new(
            types::Type::group_type_builder("schema")
                .with_fields(&mut vec![Arc::new(
                    types::Type::primitive_type_builder("col1", Type::INT32)
                        .build()
                        .unwrap(),
                )])
                .build()
                .unwrap(),
        );
        let props = Arc::new(
            WriterProperties::builder()
                .set_key_value_metadata(Some(vec![KeyValue::new(
                    "key".to_string(),
                    "value".to_string(),
                )]))
                .build(),
        );
        let mut writer =
            SerializedFileWriter::new(file.try_clone().unwrap(), schema, props).unwrap();
        writer.close().unwrap();

        let reader = SerializedFileReader::new(file).unwrap();
        assert_eq!(
            reader
                .metadata()
                .file_metadata()
                .key_value_metadata()
                .to_owned()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn test_file_writer_v2_with_metadata() {
        let file = get_temp_file("test_file_writer_v2_write_with_metadata", &[]);
        let field_logical_type = Some(LogicalType::INTEGER(IntType {
            bit_width: 8,
            is_signed: false,
        }));
        let field = Arc::new(
            types::Type::primitive_type_builder("col1", Type::INT32)
                .with_logical_type(field_logical_type.clone())
                .with_converted_type(field_logical_type.into())
                .build()
                .unwrap(),
        );
        let schema = Arc::new(
            types::Type::group_type_builder("schema")
                .with_fields(&mut vec![field.clone()])
                .build()
                .unwrap(),
        );
        let props = Arc::new(
            WriterProperties::builder()
                .set_key_value_metadata(Some(vec![KeyValue::new(
                    "key".to_string(),
                    "value".to_string(),
                )]))
                .set_writer_version(WriterVersion::PARQUET_2_0)
                .build(),
        );
        let mut writer =
            SerializedFileWriter::new(file.try_clone().unwrap(), schema, props).unwrap();
        writer.close().unwrap();

        let reader = SerializedFileReader::new(file).unwrap();

        assert_eq!(
            reader
                .metadata()
                .file_metadata()
                .key_value_metadata()
                .to_owned()
                .unwrap()
                .len(),
            1
        );

        // ARROW-11803: Test that the converted and logical types have been populated
        let fields = reader.metadata().file_metadata().schema().get_fields();
        assert_eq!(fields.len(), 1);
        let read_field = fields.get(0).unwrap();
        assert_eq!(read_field, &field);
    }

    #[test]
    fn test_file_writer_empty_row_groups() {
        let file = get_temp_file("test_file_writer_write_empty_row_groups", &[]);
        test_file_roundtrip(file, vec![]);
    }

    #[test]
    fn test_file_writer_single_row_group() {
        let file = get_temp_file("test_file_writer_write_single_row_group", &[]);
        test_file_roundtrip(file, vec![vec![1, 2, 3, 4, 5]]);
    }

    #[test]
    fn test_file_writer_multiple_row_groups() {
        let file = get_temp_file("test_file_writer_write_multiple_row_groups", &[]);
        test_file_roundtrip(
            file,
            vec![
                vec![1, 2, 3, 4, 5],
                vec![1, 2, 3],
                vec![1],
                vec![1, 2, 3, 4, 5, 6],
            ],
        );
    }

    #[test]
    fn test_file_writer_multiple_large_row_groups() {
        let file = get_temp_file("test_file_writer_multiple_large_row_groups", &[]);
        test_file_roundtrip(
            file,
            vec![vec![123; 1024], vec![124; 1000], vec![125; 15], vec![]],
        );
    }

    #[test]
    fn test_page_writer_data_pages() {
        let pages = vec![
            Page::DataPage {
                buf: ByteBufferPtr::new(vec![1, 2, 3, 4, 5, 6, 7, 8]),
                num_values: 10,
                encoding: Encoding::DELTA_BINARY_PACKED,
                def_level_encoding: Encoding::RLE,
                rep_level_encoding: Encoding::RLE,
                statistics: Some(Statistics::int32(Some(1), Some(3), None, 7, true)),
            },
            Page::DataPageV2 {
                buf: ByteBufferPtr::new(vec![4; 128]),
                num_values: 10,
                encoding: Encoding::DELTA_BINARY_PACKED,
                num_nulls: 2,
                num_rows: 12,
                def_levels_byte_len: 24,
                rep_levels_byte_len: 32,
                is_compressed: false,
                statistics: Some(Statistics::int32(Some(1), Some(3), None, 7, true)),
            },
        ];

        test_page_roundtrip(&pages[..], Compression::SNAPPY, Type::INT32);
        test_page_roundtrip(&pages[..], Compression::UNCOMPRESSED, Type::INT32);
    }

    #[test]
    fn test_page_writer_dict_pages() {
        let pages = vec![
            Page::DictionaryPage {
                buf: ByteBufferPtr::new(vec![1, 2, 3, 4, 5]),
                num_values: 5,
                encoding: Encoding::RLE_DICTIONARY,
                is_sorted: false,
            },
            Page::DataPage {
                buf: ByteBufferPtr::new(vec![1, 2, 3, 4, 5, 6, 7, 8]),
                num_values: 10,
                encoding: Encoding::DELTA_BINARY_PACKED,
                def_level_encoding: Encoding::RLE,
                rep_level_encoding: Encoding::RLE,
                statistics: Some(Statistics::int32(Some(1), Some(3), None, 7, true)),
            },
            Page::DataPageV2 {
                buf: ByteBufferPtr::new(vec![4; 128]),
                num_values: 10,
                encoding: Encoding::DELTA_BINARY_PACKED,
                num_nulls: 2,
                num_rows: 12,
                def_levels_byte_len: 24,
                rep_levels_byte_len: 32,
                is_compressed: false,
                statistics: None,
            },
        ];

        test_page_roundtrip(&pages[..], Compression::SNAPPY, Type::INT32);
        test_page_roundtrip(&pages[..], Compression::UNCOMPRESSED, Type::INT32);
    }

    const TEST_ROW_GROUP_ORDINAL: i16 = 2325;
    const TEST_COLUMN_ORDINAL: u16 = 135;

    /// Tests writing and reading pages.
    /// Physical type is for statistics only, should match any defined statistics type in
    /// pages.
    fn test_page_roundtrip(pages: &[Page], codec: Compression, physical_type: Type) {
        test_page_roundtrip_helper(pages, codec, physical_type, &None);
        test_page_roundtrip_helper(
            pages,
            codec,
            physical_type,
            &Some((
                ParquetEncryptionKey::generate_key(),
                generate_random_file_identifier(),
            )),
        );
    }

    fn test_page_roundtrip_helper(
        pages: &[Page],
        codec: Compression,
        physical_type: Type,
        encryption_info: &Option<(ParquetEncryptionKey, RandomFileIdentifier)>,
    ) {
        let mut compressed_pages = vec![];
        let mut total_num_values = 0i64;
        let mut compressor = create_codec(codec).unwrap();

        // Kind of silly because we don't enforce in this test helper function that pages are in the
        // correct order (dictionary first), but we don't have encryption in this test (yet?) anyway
        // (as that's where pages need to be in the proper order, as we need to know the aad suffix
        // in advance) so it doesn't really matter.
        let mut has_dictionary_page = false;

        for page in pages {
            let uncompressed_len = page.buffer().len();

            let compressed_page = match *page {
                Page::DataPage {
                    ref buf,
                    num_values,
                    encoding,
                    def_level_encoding,
                    rep_level_encoding,
                    ref statistics,
                } => {
                    total_num_values += num_values as i64;
                    let output_buf = compress_helper(compressor.as_mut(), buf.data());

                    Page::DataPage {
                        buf: ByteBufferPtr::new(output_buf),
                        num_values,
                        encoding,
                        def_level_encoding,
                        rep_level_encoding,
                        statistics: from_thrift(
                            physical_type,
                            to_thrift(statistics.as_ref()),
                        ),
                    }
                }
                Page::DataPageV2 {
                    ref buf,
                    num_values,
                    encoding,
                    num_nulls,
                    num_rows,
                    def_levels_byte_len,
                    rep_levels_byte_len,
                    ref statistics,
                    ..
                } => {
                    total_num_values += num_values as i64;
                    let offset = (def_levels_byte_len + rep_levels_byte_len) as usize;
                    let cmp_buf =
                        compress_helper(compressor.as_mut(), &buf.data()[offset..]);
                    let mut output_buf = Vec::from(&buf.data()[..offset]);
                    output_buf.extend_from_slice(&cmp_buf[..]);

                    Page::DataPageV2 {
                        buf: ByteBufferPtr::new(output_buf),
                        num_values,
                        encoding,
                        num_nulls,
                        num_rows,
                        def_levels_byte_len,
                        rep_levels_byte_len,
                        is_compressed: compressor.is_some(),
                        statistics: from_thrift(
                            physical_type,
                            to_thrift(statistics.as_ref()),
                        ),
                    }
                }
                Page::DictionaryPage {
                    ref buf,
                    num_values,
                    encoding,
                    is_sorted,
                } => {
                    let output_buf = compress_helper(compressor.as_mut(), buf.data());

                    has_dictionary_page = true;

                    Page::DictionaryPage {
                        buf: ByteBufferPtr::new(output_buf),
                        num_values,
                        encoding,
                        is_sorted,
                    }
                }
            };

            let compressed_page = CompressedPage::new(compressed_page, uncompressed_len);
            compressed_pages.push(compressed_page);
        }

        let mut buffer: Vec<u8> = vec![];
        let mut result_pages: Vec<Page> = vec![];
        {
            let cursor = Cursor::new(&mut buffer);
            let mut page_writer = SerializedPageWriter::new(
                cursor,
                *encryption_info,
                TEST_ROW_GROUP_ORDINAL,
                TEST_COLUMN_ORDINAL,
            );

            let mut page_ordinal = if has_dictionary_page {
                None::<u16>
            } else {
                Some(0)
            };
            for page in compressed_pages {
                page_writer.write_page(page, page_ordinal).unwrap();
                page_ordinal = Some(page_ordinal.map_or(0, |x| x + 1));
            }
            page_writer.close().unwrap();
        }
        {
            let mut page_reader = SerializedPageReader::new(
                Cursor::new(&buffer),
                *encryption_info,
                TEST_ROW_GROUP_ORDINAL,
                TEST_COLUMN_ORDINAL,
                total_num_values,
                codec,
                has_dictionary_page,
                physical_type,
            )
            .unwrap();

            while let Some(page) = page_reader.get_next_page().unwrap() {
                result_pages.push(page);
            }
        }

        assert_eq!(result_pages.len(), pages.len());
        for i in 0..result_pages.len() {
            assert_page(&result_pages[i], &pages[i]);
        }
    }

    /// Helper function to compress a slice
    fn compress_helper(compressor: Option<&mut Box<dyn Codec>>, data: &[u8]) -> Vec<u8> {
        let mut output_buf = vec![];
        if let Some(cmpr) = compressor {
            cmpr.compress(data, &mut output_buf).unwrap();
        } else {
            output_buf.extend_from_slice(data);
        }
        output_buf
    }

    /// Check if pages match.
    fn assert_page(left: &Page, right: &Page) {
        assert_eq!(left.page_type(), right.page_type());
        assert_eq!(left.buffer().data(), right.buffer().data());
        assert_eq!(left.num_values(), right.num_values());
        assert_eq!(left.encoding(), right.encoding());
        assert_eq!(to_thrift(left.statistics()), to_thrift(right.statistics()));
    }

    #[cfg(not(target_os = "windows"))]
    fn assert_magic(file: &mut File, expected: [u8; 4]) {
        let length = file.len();
        // Of course the file has to be larger than just 8, but we're just sanity-checking when checking the magic.
        assert!(length >= 8);

        let mut buf = [0xCDu8, 0xCD, 0xCD, 0xCD];
        file.read_exact_at(&mut buf[..], 0).unwrap();
        assert_eq!(buf, expected);
        file.read_exact_at(&mut buf[..], length - 4).unwrap();
        assert_eq!(buf, expected);
    }

    #[cfg(target_os = "windows")]
    fn assert_magic(file: &mut File, expected: [u8; 4]) {
        let length = file.len();
        // Of course the file has to be larger than just 8, but we're just sanity-checking when checking the magic.
        assert!(length >= 8);

        let original_position = file.stream_position().unwrap();

        let mut buf = [0xCDu8, 0xCD, 0xCD, 0xCD];
        file.seek_read(&mut buf[..], 0).unwrap();
        assert_eq!(buf, expected);
        file.seek_read(&mut buf[..], length - 4).unwrap();
        assert_eq!(buf, expected);

        file.seek(SeekFrom::Start(original_position)).unwrap();
    }

    /// File write-read roundtrip.
    /// `data` consists of arrays of values for each row group.
    fn test_file_roundtrip(mut file: File, data: Vec<Vec<i32>>) {
        test_file_roundtrip_with_encryption_key(file.try_clone().unwrap(), &data, &None);
        assert_magic(&mut file, PARQUET_MAGIC);
        file.set_len(0).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        test_file_roundtrip_with_encryption_key(
            file.try_clone().unwrap(),
            &data,
            &Some(ParquetEncryptionKey::generate_key()),
        );
        assert_magic(&mut file, PARQUET_MAGIC_ENCRYPTED_FOOTER_CUBE);
    }

    fn test_file_roundtrip_with_encryption_key(
        file: File,
        data: &Vec<Vec<i32>>,
        encryption_key: &Option<ParquetEncryptionKey>,
    ) {
        let schema = Arc::new(
            types::Type::group_type_builder("schema")
                .with_fields(&mut vec![Arc::new(
                    types::Type::primitive_type_builder("col1", Type::INT32)
                        .with_repetition(Repetition::REQUIRED)
                        .build()
                        .unwrap(),
                )])
                .build()
                .unwrap(),
        );
        let encryption_info = encryption_key.map(|key| {
            (
                ParquetEncryptionKeyInfo {
                    key_id: "a key id".to_string(),
                    key,
                },
                generate_random_file_identifier(),
            )
        });
        let props = Arc::new(
            WriterProperties::builder()
                .set_encryption_info(encryption_info.clone())
                .build(),
        );
        let mut file_writer = assert_send(
            SerializedFileWriter::new(file.try_clone().unwrap(), schema, props).unwrap(),
        );
        let mut rows: i64 = 0;

        for subset in data {
            let mut row_group_writer = file_writer.next_row_group().unwrap();
            let col_writer = row_group_writer.next_column().unwrap();
            if let Some(mut writer) = col_writer {
                match writer {
                    ColumnWriter::Int32ColumnWriter(ref mut typed) => {
                        rows +=
                            typed.write_batch(&subset[..], None, None).unwrap() as i64;
                    }
                    _ => {
                        unimplemented!();
                    }
                }
                row_group_writer.close_column(writer).unwrap();
            }
            file_writer.close_row_group(row_group_writer).unwrap();
        }

        file_writer.close().unwrap();

        let encryption_config = encryption_info.map(|(key_info, _)| {
            ParquetEncryptionConfig::new(vec![ParquetEncryptionMode::EncryptedFooter(
                key_info,
            )])
            .unwrap()
        });
        let reader = assert_send(
            SerializedFileReader::new_maybe_encrypted(file, &encryption_config).unwrap(),
        );
        assert_eq!(reader.num_row_groups(), data.len());
        assert_eq!(
            reader.metadata().file_metadata().num_rows(),
            rows,
            "row count in metadata not equal to number of rows written"
        );
        for i in 0..reader.num_row_groups() {
            let row_group_reader = reader.get_row_group(i).unwrap();
            let iter = row_group_reader.get_row_iter(None).unwrap();
            let res = iter
                .map(|elem| elem.get_int(0).unwrap())
                .collect::<Vec<i32>>();
            assert_eq!(res, data[i]);
        }
    }

    fn assert_send<T: Send>(t: T) -> T {
        t
    }

    #[test]
    fn test_bytes_writer_empty_row_groups() {
        test_bytes_roundtrip(vec![]);
    }

    #[test]
    fn test_bytes_writer_single_row_group() {
        test_bytes_roundtrip(vec![vec![1, 2, 3, 4, 5]]);
    }

    #[test]
    fn test_bytes_writer_multiple_row_groups() {
        test_bytes_roundtrip(vec![
            vec![1, 2, 3, 4, 5],
            vec![1, 2, 3],
            vec![1],
            vec![1, 2, 3, 4, 5, 6],
        ]);
    }

    fn test_bytes_roundtrip(data: Vec<Vec<i32>>) {
        test_bytes_roundtrip_helper(&data, &None);
        test_bytes_roundtrip_helper(&data, &Some(ParquetEncryptionKey::generate_key()));
    }

    fn test_bytes_roundtrip_helper(
        data: &Vec<Vec<i32>>,
        encryption_key: &Option<ParquetEncryptionKey>,
    ) {
        let cursor = InMemoryWriteableCursor::default();

        let schema = Arc::new(
            types::Type::group_type_builder("schema")
                .with_fields(&mut vec![Arc::new(
                    types::Type::primitive_type_builder("col1", Type::INT32)
                        .with_repetition(Repetition::REQUIRED)
                        .build()
                        .unwrap(),
                )])
                .build()
                .unwrap(),
        );

        let encryption_info = encryption_key.map(|key| {
            (
                ParquetEncryptionKeyInfo {
                    key_id: "a key id".to_string(),
                    key,
                },
                generate_random_file_identifier(),
            )
        });

        let mut rows: i64 = 0;
        {
            let props = Arc::new(
                WriterProperties::builder()
                    .set_encryption_info(encryption_info.clone())
                    .build(),
            );
            let mut writer =
                SerializedFileWriter::new(cursor.clone(), schema, props).unwrap();

            for subset in data {
                let mut row_group_writer = writer.next_row_group().unwrap();
                let col_writer = row_group_writer.next_column().unwrap();
                if let Some(mut writer) = col_writer {
                    match writer {
                        ColumnWriter::Int32ColumnWriter(ref mut typed) => {
                            rows += typed.write_batch(&subset[..], None, None).unwrap()
                                as i64;
                        }
                        _ => {
                            unimplemented!();
                        }
                    }
                    row_group_writer.close_column(writer).unwrap();
                }
                writer.close_row_group(row_group_writer).unwrap();
            }

            writer.close().unwrap();
        }

        let buffer = cursor.into_inner().unwrap();

        let reading_cursor = crate::file::serialized_reader::SliceableCursor::new(buffer);
        let encryption_config = encryption_info.map(|(key_info, _)| {
            ParquetEncryptionConfig::new(vec![ParquetEncryptionMode::EncryptedFooter(
                key_info,
            )])
            .unwrap()
        });
        let reader =
            SerializedFileReader::new_maybe_encrypted(reading_cursor, &encryption_config)
                .unwrap();

        assert_eq!(reader.num_row_groups(), data.len());
        assert_eq!(
            reader.metadata().file_metadata().num_rows(),
            rows,
            "row count in metadata not equal to number of rows written"
        );
        for i in 0..reader.num_row_groups() {
            let row_group_reader = reader.get_row_group(i).unwrap();
            let iter = row_group_reader.get_row_iter(None).unwrap();
            let res = iter
                .map(|elem| elem.get_int(0).unwrap())
                .collect::<Vec<i32>>();
            assert_eq!(res, data[i]);
        }
    }
}
