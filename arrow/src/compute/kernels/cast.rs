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

//! Defines cast kernels for `ArrayRef`, to convert `Array`s between
//! supported datatypes.
//!
//! Example:
//!
//! ```
//! use arrow::array::*;
//! use arrow::compute::cast;
//! use arrow::datatypes::DataType;
//! use std::sync::Arc;
//!
//! let a = Int32Array::from(vec![5, 6, 7]);
//! let array = Arc::new(a) as ArrayRef;
//! let b = cast(&array, &DataType::Float64).unwrap();
//! let c = b.as_any().downcast_ref::<Float64Array>().unwrap();
//! assert_eq!(5.0, c.value(0));
//! assert_eq!(6.0, c.value(1));
//! assert_eq!(7.0, c.value(2));
//! ```

use std::str;
use std::sync::Arc;

use crate::buffer::MutableBuffer;
use crate::compute::kernels::arithmetic::{divide, multiply};
use crate::compute::kernels::arity::unary;
use crate::compute::kernels::cast_utils::string_to_timestamp_nanos;
use crate::datatypes::*;
use crate::error::{ArrowError, Result};
use crate::{array::*, compute::take};
use crate::{buffer::Buffer, util::serialization::lexical_to_string};
use num::{NumCast, ToPrimitive};

/// CastOptions provides a way to override the default cast behaviors
#[derive(Debug)]
pub struct CastOptions {
    /// how to handle cast failures, either return NULL (safe=true) or return ERR (safe=false)
    pub safe: bool,
}

pub const DEFAULT_CAST_OPTIONS: CastOptions = CastOptions { safe: true };

/// Return true if a value of type `from_type` can be cast into a
/// value of `to_type`. Note that such as cast may be lossy.
///
/// If this function returns true to stay consistent with the `cast` kernel below.
pub fn can_cast_types(from_type: &DataType, to_type: &DataType) -> bool {
    use self::DataType::*;
    if from_type == to_type {
        return true;
    }

    match (from_type, to_type) {
        (Struct(_), _) => false,
        (_, Struct(_)) => false,
        (LargeList(list_from), LargeList(list_to)) => {
            can_cast_types(list_from.data_type(), list_to.data_type())
        }
        (List(list_from), List(list_to)) => {
            can_cast_types(list_from.data_type(), list_to.data_type())
        }
        (List(list_from), LargeList(list_to)) => {
            list_from.data_type() == list_to.data_type()
        }
        (List(_), _) => false,
        (_, List(list_to)) => can_cast_types(from_type, list_to.data_type()),
        (_, LargeList(list_to)) => can_cast_types(from_type, list_to.data_type()),
        (Dictionary(_, from_value_type), Dictionary(_, to_value_type)) => {
            can_cast_types(from_value_type, to_value_type)
        }
        (Dictionary(_, value_type), _) => can_cast_types(value_type, to_type),
        (_, Dictionary(_, value_type)) => can_cast_types(from_type, value_type),

        (_, Boolean) => DataType::is_numeric(from_type) || from_type == &Utf8,
        (Boolean, _) => DataType::is_numeric(to_type) || to_type == &Utf8,

        (Utf8, LargeUtf8) => true,
        (LargeUtf8, Utf8) => true,
        (Utf8, Date32) => true,
        (Utf8, Date64) => true,
        (Utf8, Timestamp(TimeUnit::Nanosecond, None)) => true,
        (Utf8, _) => DataType::is_numeric(to_type),
        (LargeUtf8, Date32) => true,
        (LargeUtf8, Date64) => true,
        (LargeUtf8, Timestamp(TimeUnit::Nanosecond, None)) => true,
        (LargeUtf8, _) => DataType::is_numeric(to_type),
        (Timestamp(_, _), Utf8) | (Timestamp(_, _), LargeUtf8) => true,
        (_, Utf8) | (_, LargeUtf8) => {
            DataType::is_numeric(from_type) || from_type == &Binary
        }

        // start numeric casts
        (UInt8, UInt16) => true,
        (UInt8, UInt32) => true,
        (UInt8, UInt64) => true,
        (UInt8, Int8) => true,
        (UInt8, Int16) => true,
        (UInt8, Int32) => true,
        (UInt8, Int64) => true,
        (UInt8, Float32) => true,
        (UInt8, Float64) => true,

        (UInt16, UInt8) => true,
        (UInt16, UInt32) => true,
        (UInt16, UInt64) => true,
        (UInt16, Int8) => true,
        (UInt16, Int16) => true,
        (UInt16, Int32) => true,
        (UInt16, Int64) => true,
        (UInt16, Float32) => true,
        (UInt16, Float64) => true,

        (UInt32, UInt8) => true,
        (UInt32, UInt16) => true,
        (UInt32, UInt64) => true,
        (UInt32, Int8) => true,
        (UInt32, Int16) => true,
        (UInt32, Int32) => true,
        (UInt32, Int64) => true,
        (UInt32, Float32) => true,
        (UInt32, Float64) => true,

        (UInt64, UInt8) => true,
        (UInt64, UInt16) => true,
        (UInt64, UInt32) => true,
        (UInt64, Int8) => true,
        (UInt64, Int16) => true,
        (UInt64, Int32) => true,
        (UInt64, Int64) => true,
        (UInt64, Float32) => true,
        (UInt64, Float64) => true,

        (Int8, UInt8) => true,
        (Int8, UInt16) => true,
        (Int8, UInt32) => true,
        (Int8, UInt64) => true,
        (Int8, Int16) => true,
        (Int8, Int32) => true,
        (Int8, Int64) => true,
        (Int8, Float32) => true,
        (Int8, Float64) => true,

        (Int16, UInt8) => true,
        (Int16, UInt16) => true,
        (Int16, UInt32) => true,
        (Int16, UInt64) => true,
        (Int16, Int8) => true,
        (Int16, Int32) => true,
        (Int16, Int64) => true,
        (Int16, Float32) => true,
        (Int16, Float64) => true,

        (Int32, UInt8) => true,
        (Int32, UInt16) => true,
        (Int32, UInt32) => true,
        (Int32, UInt64) => true,
        (Int32, Int8) => true,
        (Int32, Int16) => true,
        (Int32, Int64) => true,
        (Int32, Float32) => true,
        (Int32, Float64) => true,

        (Int64, UInt8) => true,
        (Int64, UInt16) => true,
        (Int64, UInt32) => true,
        (Int64, UInt64) => true,
        (Int64, Int8) => true,
        (Int64, Int16) => true,
        (Int64, Int32) => true,
        (Int64, Float32) => true,
        (Int64, Float64) => true,

        (Int64Decimal(_), UInt8) => true,
        (Int64Decimal(_), UInt16) => true,
        (Int64Decimal(_), UInt32) => true,
        (Int64Decimal(_), UInt64) => true,
        (Int64Decimal(_), Int8) => true,
        (Int64Decimal(_), Int16) => true,
        (Int64Decimal(_), Int32) => true,
        (Int64Decimal(_), Int64) => true,
        (Int64Decimal(_), Float32) => true,
        (Int64Decimal(_), Float64) => true,

        (UInt8, Int64Decimal(_)) => true,
        (UInt16, Int64Decimal(_)) => true,
        (UInt32, Int64Decimal(_)) => true,
        (UInt64, Int64Decimal(_)) => true,
        (Int8, Int64Decimal(_)) => true,
        (Int16, Int64Decimal(_)) => true,
        (Int32, Int64Decimal(_)) => true,
        (Int64, Int64Decimal(_)) => true,
        (Float32, Int64Decimal(_)) => true,
        (Float64, Int64Decimal(_)) => true,

        (Float32, UInt8) => true,
        (Float32, UInt16) => true,
        (Float32, UInt32) => true,
        (Float32, UInt64) => true,
        (Float32, Int8) => true,
        (Float32, Int16) => true,
        (Float32, Int32) => true,
        (Float32, Int64) => true,
        (Float32, Float64) => true,

        (Float64, UInt8) => true,
        (Float64, UInt16) => true,
        (Float64, UInt32) => true,
        (Float64, UInt64) => true,
        (Float64, Int8) => true,
        (Float64, Int16) => true,
        (Float64, Int32) => true,
        (Float64, Int64) => true,
        (Float64, Float32) => true,
        // end numeric casts

        // temporal casts
        (Int32, Date32) => true,
        (Int32, Date64) => true,
        (Int32, Time32(_)) => true,
        (Date32, Int32) => true,
        (Date32, Int64) => true,
        (Time32(_), Int32) => true,
        (Int64, Date64) => true,
        (Int64, Date32) => true,
        (Int64, Time64(_)) => true,
        (Date64, Int64) => true,
        (Date64, Int32) => true,
        (Time64(_), Int64) => true,
        (Date32, Date64) => true,
        (Date64, Date32) => true,
        (Time32(TimeUnit::Second), Time32(TimeUnit::Millisecond)) => true,
        (Time32(TimeUnit::Millisecond), Time32(TimeUnit::Second)) => true,
        (Time32(_), Time64(_)) => true,
        (Time64(TimeUnit::Microsecond), Time64(TimeUnit::Nanosecond)) => true,
        (Time64(TimeUnit::Nanosecond), Time64(TimeUnit::Microsecond)) => true,
        (Time64(_), Time32(to_unit)) => {
            matches!(to_unit, TimeUnit::Second | TimeUnit::Millisecond)
        }
        (Timestamp(_, _), Int64) => true,
        (Int64, Timestamp(_, _)) => true,
        (Timestamp(_, _), Timestamp(_, _)) => true,
        (Timestamp(_, _), Date32) => true,
        (Timestamp(_, _), Date64) => true,
        // date64 to timestamp might not make sense,
        (Int64, Duration(_)) => true,
        (Null, Int32) => true,
        (_, _) => false,
    }
}

macro_rules! int_decimal_append_value_to {
    ($BUILDER: expr, $CASTED:expr, $I:expr, $SCALE_MUL: expr, f64) => {
        $BUILDER.append_value(($CASTED.value($I) as f64 / $SCALE_MUL) as f64)?;
    };
    ($BUILDER: expr, $CASTED:expr, $I:expr, $SCALE_MUL: expr, f32) => {
        $BUILDER.append_value(($CASTED.value($I) as f32 / $SCALE_MUL) as f32)?;
    };
    ($BUILDER: expr, $CASTED:expr, $I:expr, $SCALE_MUL: expr, $TO_TYPE: ty) => {
        $BUILDER.append_value(($CASTED.value($I) / $SCALE_MUL) as $TO_TYPE)?;
    };
}

macro_rules! int_decimal_cast_to_array {
    ($ARRAY:expr, $DECIMAL_ARRAY: ident, $TO_ARRAY_BUILDER: ident, $TO_TYPE: tt, $SCALE_MUL: expr) => {{
        let casted = $ARRAY.as_any().downcast_ref::<$DECIMAL_ARRAY>().unwrap();
        let mut b = $TO_ARRAY_BUILDER::new($ARRAY.len());
        for i in 0..$ARRAY.len() {
            if $ARRAY.is_null(i) {
                b.append_null()?;
            } else {
                int_decimal_append_value_to!(b, casted, i, $SCALE_MUL, $TO_TYPE);
            }
        }

        Ok(Arc::new(b.finish()) as ArrayRef)
    }};
}

macro_rules! int_decimal_cast_from_array {
    ($ARRAY:expr, $DECIMAL_ARRAY_BUILDER: ident, $FROM_ARRAY_TYPE: ident, $FROM_TYPE: tt, $SCALE_MUL: expr) => {{
        let casted = $ARRAY.as_any().downcast_ref::<$FROM_ARRAY_TYPE>().unwrap();
        let mut b = $DECIMAL_ARRAY_BUILDER::new($ARRAY.len());
        for i in 0..$ARRAY.len() {
            if $ARRAY.is_null(i) {
                b.append_null()?;
            } else {
                b.append_value((casted.value(i) * ($SCALE_MUL as $FROM_TYPE)) as i64)?;
            }
        }

        Ok(Arc::new(b.finish()) as ArrayRef)
    }};
}

macro_rules! int_decimal_cast_to {
    ($ARRAY:expr, $TO_ARRAY_BUILDER: ident, f32, $SCALE: expr) => {{
        match $SCALE {
            0 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal0Array,
                $TO_ARRAY_BUILDER,
                f32,
                1.0f32
            ),
            1 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal1Array,
                $TO_ARRAY_BUILDER,
                f32,
                10.0f32
            ),
            2 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal2Array,
                $TO_ARRAY_BUILDER,
                f32,
                100.0f32
            ),
            3 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal3Array,
                $TO_ARRAY_BUILDER,
                f32,
                1000.0f32
            ),
            4 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal4Array,
                $TO_ARRAY_BUILDER,
                f32,
                10000.0f32
            ),
            5 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal5Array,
                $TO_ARRAY_BUILDER,
                f32,
                100000.0f32
            ),
            10 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal10Array,
                $TO_ARRAY_BUILDER,
                f32,
                10000000000.0f32
            ),
            x => panic!("Unsupported scale: {}", x),
        }
    }};
    ($ARRAY:expr, $TO_ARRAY_BUILDER: ident, f64, $SCALE: expr) => {{
        match $SCALE {
            0 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal0Array,
                $TO_ARRAY_BUILDER,
                f64,
                1.0f64
            ),
            1 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal1Array,
                $TO_ARRAY_BUILDER,
                f64,
                10.0f64
            ),
            2 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal2Array,
                $TO_ARRAY_BUILDER,
                f64,
                100.0f64
            ),
            3 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal3Array,
                $TO_ARRAY_BUILDER,
                f64,
                1000.0f64
            ),
            4 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal4Array,
                $TO_ARRAY_BUILDER,
                f64,
                10000.0f64
            ),
            5 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal5Array,
                $TO_ARRAY_BUILDER,
                f64,
                100000.0f64
            ),
            10 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal10Array,
                $TO_ARRAY_BUILDER,
                f64,
                10000000000.0f64
            ),
            x => panic!("Unsupported scale: {}", x),
        }
    }};
    ($ARRAY:expr, $TO_ARRAY_BUILDER: ident, $TO_TYPE: ty, $SCALE: expr) => {{
        match $SCALE {
            0 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal0Array,
                $TO_ARRAY_BUILDER,
                $TO_TYPE,
                1
            ),
            1 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal1Array,
                $TO_ARRAY_BUILDER,
                $TO_TYPE,
                10
            ),
            2 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal2Array,
                $TO_ARRAY_BUILDER,
                $TO_TYPE,
                100
            ),
            3 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal3Array,
                $TO_ARRAY_BUILDER,
                $TO_TYPE,
                1000
            ),
            4 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal4Array,
                $TO_ARRAY_BUILDER,
                $TO_TYPE,
                10000
            ),
            5 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal5Array,
                $TO_ARRAY_BUILDER,
                $TO_TYPE,
                100000
            ),
            10 => int_decimal_cast_to_array!(
                $ARRAY,
                Int64Decimal10Array,
                $TO_ARRAY_BUILDER,
                $TO_TYPE,
                10000000000
            ),
            x => panic!("Unsupported scale: {}", x),
        }
    }};
}

macro_rules! int_decimal_cast_from {
    ($ARRAY:expr, $ARRAY_TYPE: ident, $TO_TYPE: ty, $SCALE: expr) => {{
        match $SCALE {
            0 => int_decimal_cast_from_array!(
                $ARRAY,
                Int64Decimal0Builder,
                $ARRAY_TYPE,
                $TO_TYPE,
                1i64
            ),
            1 => int_decimal_cast_from_array!(
                $ARRAY,
                Int64Decimal1Builder,
                $ARRAY_TYPE,
                $TO_TYPE,
                10i64
            ),
            2 => int_decimal_cast_from_array!(
                $ARRAY,
                Int64Decimal2Builder,
                $ARRAY_TYPE,
                $TO_TYPE,
                100i64
            ),
            3 => int_decimal_cast_from_array!(
                $ARRAY,
                Int64Decimal3Builder,
                $ARRAY_TYPE,
                $TO_TYPE,
                1000i64
            ),
            4 => int_decimal_cast_from_array!(
                $ARRAY,
                Int64Decimal4Builder,
                $ARRAY_TYPE,
                $TO_TYPE,
                10000i64
            ),
            5 => int_decimal_cast_from_array!(
                $ARRAY,
                Int64Decimal5Builder,
                $ARRAY_TYPE,
                $TO_TYPE,
                100000i64
            ),
            10 => int_decimal_cast_from_array!(
                $ARRAY,
                Int64Decimal10Builder,
                $ARRAY_TYPE,
                $TO_TYPE,
                10000000000i64
            ),
            x => panic!("Unsupported scale: {}", x),
        }
    }};
}

/// Cast `array` to the provided data type and return a new Array with
/// type `to_type`, if possible.
///
/// Behavior:
/// * Boolean to Utf8: `true` => '1', `false` => `0`
/// * Utf8 to numeric: strings that can't be parsed to numbers return null, float strings
///   in integer casts return null
/// * Numeric to boolean: 0 returns `false`, any other value returns `true`
/// * List to List: the underlying data type is cast
/// * Primitive to List: a list array with 1 value per slot is created
/// * Date32 and Date64: precision lost when going to higher interval
/// * Time32 and Time64: precision lost when going to higher interval
/// * Timestamp and Date{32|64}: precision lost when going to higher interval
/// * Temporal to/from backing primitive: zero-copy with data type change
///
/// Unsupported Casts
/// * To or from `StructArray`
/// * List to primitive
/// * Utf8 to boolean
/// * Interval and duration
pub fn cast(array: &ArrayRef, to_type: &DataType) -> Result<ArrayRef> {
    cast_with_options(array, to_type, &DEFAULT_CAST_OPTIONS)
}

/// Cast `array` to the provided data type and return a new Array with
/// type `to_type`, if possible. It accepts `CastOptions` to allow consumers
/// to configure cast behavior.
///
/// Behavior:
/// * Boolean to Utf8: `true` => '1', `false` => `0`
/// * Utf8 to numeric: strings that can't be parsed to numbers return null, float strings
///   in integer casts return null
/// * Numeric to boolean: 0 returns `false`, any other value returns `true`
/// * List to List: the underlying data type is cast
/// * Primitive to List: a list array with 1 value per slot is created
/// * Date32 and Date64: precision lost when going to higher interval
/// * Time32 and Time64: precision lost when going to higher interval
/// * Timestamp and Date{32|64}: precision lost when going to higher interval
/// * Temporal to/from backing primitive: zero-copy with data type change
///
/// Unsupported Casts
/// * To or from `StructArray`
/// * List to primitive
/// * Utf8 to boolean
/// * Interval and duration
pub fn cast_with_options(
    array: &ArrayRef,
    to_type: &DataType,
    cast_options: &CastOptions,
) -> Result<ArrayRef> {
    use DataType::*;
    let from_type = array.data_type();

    // clone array if types are the same
    if from_type == to_type {
        return Ok(array.clone());
    }
    match (from_type, to_type) {
        (Struct(_), _) => Err(ArrowError::CastError(
            "Cannot cast from struct to other types".to_string(),
        )),
        (_, Struct(_)) => Err(ArrowError::CastError(
            "Cannot cast to struct from other types".to_string(),
        )),
        (List(_), List(ref to)) => {
            cast_list_inner::<i32>(array, to, to_type, cast_options)
        }
        (LargeList(_), LargeList(ref to)) => {
            cast_list_inner::<i64>(array, to, to_type, cast_options)
        }
        (List(list_from), LargeList(list_to)) => {
            if list_to.data_type() != list_from.data_type() {
                Err(ArrowError::CastError(
                    "cannot cast list to large-list with different child data".into(),
                ))
            } else {
                cast_list_container::<i32, i64>(&**array, cast_options)
            }
        }
        (LargeList(list_from), List(list_to)) => {
            if list_to.data_type() != list_from.data_type() {
                Err(ArrowError::CastError(
                    "cannot cast large-list to list with different child data".into(),
                ))
            } else {
                cast_list_container::<i64, i32>(&**array, cast_options)
            }
        }
        (List(_), _) => Err(ArrowError::CastError(
            "Cannot cast list to non-list data types".to_string(),
        )),
        (_, List(ref to)) => {
            cast_primitive_to_list::<i32>(array, to, to_type, cast_options)
        }
        (_, LargeList(ref to)) => {
            cast_primitive_to_list::<i64>(array, to, to_type, cast_options)
        }
        (Dictionary(index_type, _), _) => match **index_type {
            DataType::Int8 => dictionary_cast::<Int8Type>(array, to_type, cast_options),
            DataType::Int16 => dictionary_cast::<Int16Type>(array, to_type, cast_options),
            DataType::Int32 => dictionary_cast::<Int32Type>(array, to_type, cast_options),
            DataType::Int64 => dictionary_cast::<Int64Type>(array, to_type, cast_options),
            DataType::UInt8 => dictionary_cast::<UInt8Type>(array, to_type, cast_options),
            DataType::UInt16 => {
                dictionary_cast::<UInt16Type>(array, to_type, cast_options)
            }
            DataType::UInt32 => {
                dictionary_cast::<UInt32Type>(array, to_type, cast_options)
            }
            DataType::UInt64 => {
                dictionary_cast::<UInt64Type>(array, to_type, cast_options)
            }
            _ => Err(ArrowError::CastError(format!(
                "Casting from dictionary type {:?} to {:?} not supported",
                from_type, to_type,
            ))),
        },
        (_, Dictionary(index_type, value_type)) => match **index_type {
            DataType::Int8 => {
                cast_to_dictionary::<Int8Type>(array, value_type, cast_options)
            }
            DataType::Int16 => {
                cast_to_dictionary::<Int16Type>(array, value_type, cast_options)
            }
            DataType::Int32 => {
                cast_to_dictionary::<Int32Type>(array, value_type, cast_options)
            }
            DataType::Int64 => {
                cast_to_dictionary::<Int64Type>(array, value_type, cast_options)
            }
            DataType::UInt8 => {
                cast_to_dictionary::<UInt8Type>(array, value_type, cast_options)
            }
            DataType::UInt16 => {
                cast_to_dictionary::<UInt16Type>(array, value_type, cast_options)
            }
            DataType::UInt32 => {
                cast_to_dictionary::<UInt32Type>(array, value_type, cast_options)
            }
            DataType::UInt64 => {
                cast_to_dictionary::<UInt64Type>(array, value_type, cast_options)
            }
            _ => Err(ArrowError::CastError(format!(
                "Casting from type {:?} to dictionary type {:?} not supported",
                from_type, to_type,
            ))),
        },
        (_, Boolean) => match from_type {
            UInt8 => cast_numeric_to_bool::<UInt8Type>(array),
            UInt16 => cast_numeric_to_bool::<UInt16Type>(array),
            UInt32 => cast_numeric_to_bool::<UInt32Type>(array),
            UInt64 => cast_numeric_to_bool::<UInt64Type>(array),
            Int8 => cast_numeric_to_bool::<Int8Type>(array),
            Int16 => cast_numeric_to_bool::<Int16Type>(array),
            Int32 => cast_numeric_to_bool::<Int32Type>(array),
            Int64 => cast_numeric_to_bool::<Int64Type>(array),
            Float32 => cast_numeric_to_bool::<Float32Type>(array),
            Float64 => cast_numeric_to_bool::<Float64Type>(array),
            Utf8 => {
                let array = array.as_any().downcast_ref::<StringArray>().unwrap();
                let mut builder = BooleanArray::builder(array.len());
                for i in 0..array.len() {
                    if array.is_valid(i) {
                        let value = array.value(i);
                        if value.to_lowercase() == "true" || value == "1" {
                            builder.append_value(true)?;
                        } else if value.to_lowercase() == "false" || value == "0" {
                            builder.append_value(false)?;
                        } else {
                            // TODO arrow doesn't expect errors if can_cast is true
                            builder.append_null()?;
                        };
                    } else {
                        builder.append_null()?;
                    }
                }
                Ok(Arc::new(builder.finish()))
            }
            _ => Err(ArrowError::CastError(format!(
                "Casting from {:?} to {:?} not supported",
                from_type, to_type,
            ))),
        },
        (Boolean, _) => match to_type {
            UInt8 => cast_bool_to_numeric::<UInt8Type>(array, cast_options),
            UInt16 => cast_bool_to_numeric::<UInt16Type>(array, cast_options),
            UInt32 => cast_bool_to_numeric::<UInt32Type>(array, cast_options),
            UInt64 => cast_bool_to_numeric::<UInt64Type>(array, cast_options),
            Int8 => cast_bool_to_numeric::<Int8Type>(array, cast_options),
            Int16 => cast_bool_to_numeric::<Int16Type>(array, cast_options),
            Int32 => cast_bool_to_numeric::<Int32Type>(array, cast_options),
            Int64 => cast_bool_to_numeric::<Int64Type>(array, cast_options),
            Float32 => cast_bool_to_numeric::<Float32Type>(array, cast_options),
            Float64 => cast_bool_to_numeric::<Float64Type>(array, cast_options),
            Utf8 => {
                let array = array.as_any().downcast_ref::<BooleanArray>().unwrap();
                Ok(Arc::new(
                    array
                        .iter()
                        .map(|value| value.map(|value| if value { "1" } else { "0" }))
                        .collect::<StringArray>(),
                ))
            }
            _ => Err(ArrowError::CastError(format!(
                "Casting from {:?} to {:?} not supported",
                from_type, to_type,
            ))),
        },
        (Utf8, _) => match to_type {
            LargeUtf8 => cast_str_container::<i32, i64>(&**array),
            UInt8 => cast_string_to_numeric::<UInt8Type, i32>(array, cast_options),
            UInt16 => cast_string_to_numeric::<UInt16Type, i32>(array, cast_options),
            UInt32 => cast_string_to_numeric::<UInt32Type, i32>(array, cast_options),
            UInt64 => cast_string_to_numeric::<UInt64Type, i32>(array, cast_options),
            Int64Decimal(scale) => {
                let float_from_string =
                    cast_string_to_numeric::<Float64Type, i32>(array, cast_options)?;
                int_decimal_cast_from!(float_from_string, Float64Array, f64, scale)
            }
            Int8 => cast_string_to_numeric::<Int8Type, i32>(array, cast_options),
            Int16 => cast_string_to_numeric::<Int16Type, i32>(array, cast_options),
            Int32 => cast_string_to_numeric::<Int32Type, i32>(array, cast_options),
            Int64 => cast_string_to_numeric::<Int64Type, i32>(array, cast_options),
            Float32 => cast_string_to_numeric::<Float32Type, i32>(array, cast_options),
            Float64 => cast_string_to_numeric::<Float64Type, i32>(array, cast_options),
            Date32 => cast_string_to_date32::<i32>(&**array, cast_options),
            Date64 => cast_string_to_date64::<i32>(&**array, cast_options),
            Timestamp(TimeUnit::Nanosecond, None) => {
                cast_string_to_timestamp_ns::<i32>(&**array, cast_options)
            }
            _ => Err(ArrowError::CastError(format!(
                "Casting from {:?} to {:?} not supported",
                from_type, to_type,
            ))),
        },
        (_, Utf8) => match from_type {
            LargeUtf8 => cast_str_container::<i64, i32>(&**array),
            UInt8 => cast_numeric_to_string::<UInt8Type, i32>(array),
            UInt16 => cast_numeric_to_string::<UInt16Type, i32>(array),
            UInt32 => cast_numeric_to_string::<UInt32Type, i32>(array),
            UInt64 => cast_numeric_to_string::<UInt64Type, i32>(array),
            Int8 => cast_numeric_to_string::<Int8Type, i32>(array),
            Int16 => cast_numeric_to_string::<Int16Type, i32>(array),
            Int32 => cast_numeric_to_string::<Int32Type, i32>(array),
            Int64 => cast_numeric_to_string::<Int64Type, i32>(array),
            Int64Decimal(scale) => {
                let float_array: Result<ArrayRef> =
                    int_decimal_cast_to!(array, Float64Builder, f64, scale);
                cast_numeric_to_string::<Float64Type, i32>(&float_array?)
            }
            Float32 => cast_numeric_to_string::<Float32Type, i32>(array),
            Float64 => cast_numeric_to_string::<Float64Type, i32>(array),
            Timestamp(unit, _) => match unit {
                TimeUnit::Nanosecond => {
                    cast_timestamp_to_string::<TimestampNanosecondType, i32>(array)
                }
                TimeUnit::Microsecond => {
                    cast_timestamp_to_string::<TimestampMicrosecondType, i32>(array)
                }
                TimeUnit::Millisecond => {
                    cast_timestamp_to_string::<TimestampMillisecondType, i32>(array)
                }
                TimeUnit::Second => {
                    cast_timestamp_to_string::<TimestampSecondType, i32>(array)
                }
            },
            Binary => {
                let array = array.as_any().downcast_ref::<BinaryArray>().unwrap();
                Ok(Arc::new(
                    array
                        .iter()
                        .map(|maybe_value| match maybe_value {
                            Some(value) => {
                                let result = str::from_utf8(value);
                                if cast_options.safe {
                                    Ok(result.ok())
                                } else {
                                    Some(result.map_err(|_| {
                                        ArrowError::CastError(
                                            "Cannot cast binary to string".to_string(),
                                        )
                                    }))
                                    .transpose()
                                }
                            }
                            None => Ok(None),
                        })
                        .collect::<Result<StringArray>>()?,
                ))
            }
            _ => Err(ArrowError::CastError(format!(
                "Casting from {:?} to {:?} not supported",
                from_type, to_type,
            ))),
        },
        (_, LargeUtf8) => match from_type {
            UInt8 => cast_numeric_to_string::<UInt8Type, i64>(array),
            UInt16 => cast_numeric_to_string::<UInt16Type, i64>(array),
            UInt32 => cast_numeric_to_string::<UInt32Type, i64>(array),
            UInt64 => cast_numeric_to_string::<UInt64Type, i64>(array),
            Int8 => cast_numeric_to_string::<Int8Type, i64>(array),
            Int16 => cast_numeric_to_string::<Int16Type, i64>(array),
            Int32 => cast_numeric_to_string::<Int32Type, i64>(array),
            Int64 => cast_numeric_to_string::<Int64Type, i64>(array),
            Int64Decimal(scale) => {
                let float_array: Result<ArrayRef> =
                    int_decimal_cast_to!(array, Float64Builder, f64, scale);
                cast_numeric_to_string::<Float64Type, i64>(&float_array?)
            }
            Float32 => cast_numeric_to_string::<Float32Type, i64>(array),
            Float64 => cast_numeric_to_string::<Float64Type, i64>(array),
            Timestamp(unit, _) => match unit {
                TimeUnit::Nanosecond => {
                    cast_timestamp_to_string::<TimestampNanosecondType, i64>(array)
                }
                TimeUnit::Microsecond => {
                    cast_timestamp_to_string::<TimestampMicrosecondType, i64>(array)
                }
                TimeUnit::Millisecond => {
                    cast_timestamp_to_string::<TimestampMillisecondType, i64>(array)
                }
                TimeUnit::Second => {
                    cast_timestamp_to_string::<TimestampSecondType, i64>(array)
                }
            },
            Binary => {
                let array = array.as_any().downcast_ref::<BinaryArray>().unwrap();
                Ok(Arc::new(
                    array
                        .iter()
                        .map(|maybe_value| match maybe_value {
                            Some(value) => {
                                let result = str::from_utf8(value);
                                if cast_options.safe {
                                    Ok(result.ok())
                                } else {
                                    Some(result.map_err(|_| {
                                        ArrowError::CastError(
                                            "Cannot cast binary to string".to_string(),
                                        )
                                    }))
                                    .transpose()
                                }
                            }
                            None => Ok(None),
                        })
                        .collect::<Result<LargeStringArray>>()?,
                ))
            }
            _ => Err(ArrowError::CastError(format!(
                "Casting from {:?} to {:?} not supported",
                from_type, to_type,
            ))),
        },
        (LargeUtf8, _) => match to_type {
            UInt8 => cast_string_to_numeric::<UInt8Type, i64>(array, cast_options),
            UInt16 => cast_string_to_numeric::<UInt16Type, i64>(array, cast_options),
            UInt32 => cast_string_to_numeric::<UInt32Type, i64>(array, cast_options),
            UInt64 => cast_string_to_numeric::<UInt64Type, i64>(array, cast_options),
            Int8 => cast_string_to_numeric::<Int8Type, i64>(array, cast_options),
            Int16 => cast_string_to_numeric::<Int16Type, i64>(array, cast_options),
            Int32 => cast_string_to_numeric::<Int32Type, i64>(array, cast_options),
            Int64 => cast_string_to_numeric::<Int64Type, i64>(array, cast_options),
            Float32 => cast_string_to_numeric::<Float32Type, i64>(array, cast_options),
            Float64 => cast_string_to_numeric::<Float64Type, i64>(array, cast_options),
            Date32 => cast_string_to_date32::<i64>(&**array, cast_options),
            Date64 => cast_string_to_date64::<i64>(&**array, cast_options),
            Timestamp(TimeUnit::Nanosecond, None) => {
                cast_string_to_timestamp_ns::<i64>(&**array, cast_options)
            }
            _ => Err(ArrowError::CastError(format!(
                "Casting from {:?} to {:?} not supported",
                from_type, to_type,
            ))),
        },

        // start numeric casts
        (UInt8, UInt16) => cast_numeric_arrays::<UInt8Type, UInt16Type>(array),
        (UInt8, UInt32) => cast_numeric_arrays::<UInt8Type, UInt32Type>(array),
        (UInt8, UInt64) => cast_numeric_arrays::<UInt8Type, UInt64Type>(array),
        (UInt8, Int8) => cast_numeric_arrays::<UInt8Type, Int8Type>(array),
        (UInt8, Int16) => cast_numeric_arrays::<UInt8Type, Int16Type>(array),
        (UInt8, Int32) => cast_numeric_arrays::<UInt8Type, Int32Type>(array),
        (UInt8, Int64) => cast_numeric_arrays::<UInt8Type, Int64Type>(array),
        (UInt8, Float32) => cast_numeric_arrays::<UInt8Type, Float32Type>(array),
        (UInt8, Float64) => cast_numeric_arrays::<UInt8Type, Float64Type>(array),

        (UInt16, UInt8) => cast_numeric_arrays::<UInt16Type, UInt8Type>(array),
        (UInt16, UInt32) => cast_numeric_arrays::<UInt16Type, UInt32Type>(array),
        (UInt16, UInt64) => cast_numeric_arrays::<UInt16Type, UInt64Type>(array),
        (UInt16, Int8) => cast_numeric_arrays::<UInt16Type, Int8Type>(array),
        (UInt16, Int16) => cast_numeric_arrays::<UInt16Type, Int16Type>(array),
        (UInt16, Int32) => cast_numeric_arrays::<UInt16Type, Int32Type>(array),
        (UInt16, Int64) => cast_numeric_arrays::<UInt16Type, Int64Type>(array),
        (UInt16, Float32) => cast_numeric_arrays::<UInt16Type, Float32Type>(array),
        (UInt16, Float64) => cast_numeric_arrays::<UInt16Type, Float64Type>(array),

        (UInt32, UInt8) => cast_numeric_arrays::<UInt32Type, UInt8Type>(array),
        (UInt32, UInt16) => cast_numeric_arrays::<UInt32Type, UInt16Type>(array),
        (UInt32, UInt64) => cast_numeric_arrays::<UInt32Type, UInt64Type>(array),
        (UInt32, Int8) => cast_numeric_arrays::<UInt32Type, Int8Type>(array),
        (UInt32, Int16) => cast_numeric_arrays::<UInt32Type, Int16Type>(array),
        (UInt32, Int32) => cast_numeric_arrays::<UInt32Type, Int32Type>(array),
        (UInt32, Int64) => cast_numeric_arrays::<UInt32Type, Int64Type>(array),
        (UInt32, Float32) => cast_numeric_arrays::<UInt32Type, Float32Type>(array),
        (UInt32, Float64) => cast_numeric_arrays::<UInt32Type, Float64Type>(array),

        (UInt64, UInt8) => cast_numeric_arrays::<UInt64Type, UInt8Type>(array),
        (UInt64, UInt16) => cast_numeric_arrays::<UInt64Type, UInt16Type>(array),
        (UInt64, UInt32) => cast_numeric_arrays::<UInt64Type, UInt32Type>(array),
        (UInt64, Int8) => cast_numeric_arrays::<UInt64Type, Int8Type>(array),
        (UInt64, Int16) => cast_numeric_arrays::<UInt64Type, Int16Type>(array),
        (UInt64, Int32) => cast_numeric_arrays::<UInt64Type, Int32Type>(array),
        (UInt64, Int64) => cast_numeric_arrays::<UInt64Type, Int64Type>(array),
        (UInt64, Float32) => cast_numeric_arrays::<UInt64Type, Float32Type>(array),
        (UInt64, Float64) => cast_numeric_arrays::<UInt64Type, Float64Type>(array),

        (Int8, UInt8) => cast_numeric_arrays::<Int8Type, UInt8Type>(array),
        (Int8, UInt16) => cast_numeric_arrays::<Int8Type, UInt16Type>(array),
        (Int8, UInt32) => cast_numeric_arrays::<Int8Type, UInt32Type>(array),
        (Int8, UInt64) => cast_numeric_arrays::<Int8Type, UInt64Type>(array),
        (Int8, Int16) => cast_numeric_arrays::<Int8Type, Int16Type>(array),
        (Int8, Int32) => cast_numeric_arrays::<Int8Type, Int32Type>(array),
        (Int8, Int64) => cast_numeric_arrays::<Int8Type, Int64Type>(array),
        (Int8, Float32) => cast_numeric_arrays::<Int8Type, Float32Type>(array),
        (Int8, Float64) => cast_numeric_arrays::<Int8Type, Float64Type>(array),

        (Int16, UInt8) => cast_numeric_arrays::<Int16Type, UInt8Type>(array),
        (Int16, UInt16) => cast_numeric_arrays::<Int16Type, UInt16Type>(array),
        (Int16, UInt32) => cast_numeric_arrays::<Int16Type, UInt32Type>(array),
        (Int16, UInt64) => cast_numeric_arrays::<Int16Type, UInt64Type>(array),
        (Int16, Int8) => cast_numeric_arrays::<Int16Type, Int8Type>(array),
        (Int16, Int32) => cast_numeric_arrays::<Int16Type, Int32Type>(array),
        (Int16, Int64) => cast_numeric_arrays::<Int16Type, Int64Type>(array),
        (Int16, Float32) => cast_numeric_arrays::<Int16Type, Float32Type>(array),
        (Int16, Float64) => cast_numeric_arrays::<Int16Type, Float64Type>(array),

        (Int32, UInt8) => cast_numeric_arrays::<Int32Type, UInt8Type>(array),
        (Int32, UInt16) => cast_numeric_arrays::<Int32Type, UInt16Type>(array),
        (Int32, UInt32) => cast_numeric_arrays::<Int32Type, UInt32Type>(array),
        (Int32, UInt64) => cast_numeric_arrays::<Int32Type, UInt64Type>(array),
        (Int32, Int8) => cast_numeric_arrays::<Int32Type, Int8Type>(array),
        (Int32, Int16) => cast_numeric_arrays::<Int32Type, Int16Type>(array),
        (Int32, Int64) => cast_numeric_arrays::<Int32Type, Int64Type>(array),
        (Int32, Float32) => cast_numeric_arrays::<Int32Type, Float32Type>(array),
        (Int32, Float64) => cast_numeric_arrays::<Int32Type, Float64Type>(array),

        (Int64, UInt8) => cast_numeric_arrays::<Int64Type, UInt8Type>(array),
        (Int64, UInt16) => cast_numeric_arrays::<Int64Type, UInt16Type>(array),
        (Int64, UInt32) => cast_numeric_arrays::<Int64Type, UInt32Type>(array),
        (Int64, UInt64) => cast_numeric_arrays::<Int64Type, UInt64Type>(array),
        (Int64, Int8) => cast_numeric_arrays::<Int64Type, Int8Type>(array),
        (Int64, Int16) => cast_numeric_arrays::<Int64Type, Int16Type>(array),
        (Int64, Int32) => cast_numeric_arrays::<Int64Type, Int32Type>(array),
        (Int64, Float32) => cast_numeric_arrays::<Int64Type, Float32Type>(array),
        (Int64, Float64) => cast_numeric_arrays::<Int64Type, Float64Type>(array),

        (Int64Decimal(scale), UInt8) => {
            int_decimal_cast_to!(array, UInt8Builder, u8, scale)
        }
        (Int64Decimal(scale), UInt16) => {
            int_decimal_cast_to!(array, UInt16Builder, u16, scale)
        }
        (Int64Decimal(scale), UInt32) => {
            int_decimal_cast_to!(array, UInt32Builder, u32, scale)
        }
        (Int64Decimal(scale), UInt64) => {
            int_decimal_cast_to!(array, UInt64Builder, u64, scale)
        }
        (Int64Decimal(scale), Int8) => {
            int_decimal_cast_to!(array, Int8Builder, i8, scale)
        }
        (Int64Decimal(scale), Int16) => {
            int_decimal_cast_to!(array, Int16Builder, i16, scale)
        }
        (Int64Decimal(scale), Int32) => {
            int_decimal_cast_to!(array, Int32Builder, i32, scale)
        }
        (Int64Decimal(scale), Int64) => {
            int_decimal_cast_to!(array, Int64Builder, i64, scale)
        }
        (Int64Decimal(scale), Float32) => {
            int_decimal_cast_to!(array, Float32Builder, f32, scale)
        }
        (Int64Decimal(scale), Float64) => {
            int_decimal_cast_to!(array, Float64Builder, f64, scale)
        }

        (UInt8, Int64Decimal(scale)) => {
            int_decimal_cast_from!(array, UInt8Array, u8, scale)
        }
        (UInt16, Int64Decimal(scale)) => {
            int_decimal_cast_from!(array, UInt16Array, u16, scale)
        }
        (UInt32, Int64Decimal(scale)) => {
            int_decimal_cast_from!(array, UInt32Array, u32, scale)
        }
        (UInt64, Int64Decimal(scale)) => {
            int_decimal_cast_from!(array, UInt64Array, u64, scale)
        }
        (Int8, Int64Decimal(scale)) => {
            int_decimal_cast_from!(array, Int8Array, i8, scale)
        }
        (Int16, Int64Decimal(scale)) => {
            int_decimal_cast_from!(array, Int16Array, i16, scale)
        }
        (Int32, Int64Decimal(scale)) => {
            int_decimal_cast_from!(array, Int32Array, i32, scale)
        }
        (Int64, Int64Decimal(scale)) => {
            int_decimal_cast_from!(array, Int64Array, i64, scale)
        }
        (Float32, Int64Decimal(scale)) => {
            int_decimal_cast_from!(array, Float32Array, f32, scale)
        }
        (Float64, Int64Decimal(scale)) => {
            int_decimal_cast_from!(array, Float64Array, f64, scale)
        }

        (Float32, UInt8) => cast_numeric_arrays::<Float32Type, UInt8Type>(array),
        (Float32, UInt16) => cast_numeric_arrays::<Float32Type, UInt16Type>(array),
        (Float32, UInt32) => cast_numeric_arrays::<Float32Type, UInt32Type>(array),
        (Float32, UInt64) => cast_numeric_arrays::<Float32Type, UInt64Type>(array),
        (Float32, Int8) => cast_numeric_arrays::<Float32Type, Int8Type>(array),
        (Float32, Int16) => cast_numeric_arrays::<Float32Type, Int16Type>(array),
        (Float32, Int32) => cast_numeric_arrays::<Float32Type, Int32Type>(array),
        (Float32, Int64) => cast_numeric_arrays::<Float32Type, Int64Type>(array),
        (Float32, Float64) => cast_numeric_arrays::<Float32Type, Float64Type>(array),

        (Float64, UInt8) => cast_numeric_arrays::<Float64Type, UInt8Type>(array),
        (Float64, UInt16) => cast_numeric_arrays::<Float64Type, UInt16Type>(array),
        (Float64, UInt32) => cast_numeric_arrays::<Float64Type, UInt32Type>(array),
        (Float64, UInt64) => cast_numeric_arrays::<Float64Type, UInt64Type>(array),
        (Float64, Int8) => cast_numeric_arrays::<Float64Type, Int8Type>(array),
        (Float64, Int16) => cast_numeric_arrays::<Float64Type, Int16Type>(array),
        (Float64, Int32) => cast_numeric_arrays::<Float64Type, Int32Type>(array),
        (Float64, Int64) => cast_numeric_arrays::<Float64Type, Int64Type>(array),
        (Float64, Float32) => cast_numeric_arrays::<Float64Type, Float32Type>(array),
        // end numeric casts

        // temporal casts
        (Int32, Date32) => cast_array_data::<Date32Type>(array, to_type.clone()),
        (Int32, Date64) => cast_with_options(
            &cast_with_options(array, &DataType::Date32, &cast_options)?,
            &DataType::Date64,
            &cast_options,
        ),
        (Int32, Time32(TimeUnit::Second)) => {
            cast_array_data::<Time32SecondType>(array, to_type.clone())
        }
        (Int32, Time32(TimeUnit::Millisecond)) => {
            cast_array_data::<Time32MillisecondType>(array, to_type.clone())
        }
        // No support for microsecond/nanosecond with i32
        (Date32, Int32) => cast_array_data::<Int32Type>(array, to_type.clone()),
        (Date32, Int64) => cast_with_options(
            &cast_with_options(array, &DataType::Int32, cast_options)?,
            &DataType::Int64,
            &cast_options,
        ),
        (Time32(_), Int32) => cast_array_data::<Int32Type>(array, to_type.clone()),
        (Int64, Date64) => cast_array_data::<Date64Type>(array, to_type.clone()),
        (Int64, Date32) => cast_with_options(
            &cast_with_options(array, &DataType::Int32, &cast_options)?,
            &DataType::Date32,
            &cast_options,
        ),
        // No support for second/milliseconds with i64
        (Int64, Time64(TimeUnit::Microsecond)) => {
            cast_array_data::<Time64MicrosecondType>(array, to_type.clone())
        }
        (Int64, Time64(TimeUnit::Nanosecond)) => {
            cast_array_data::<Time64NanosecondType>(array, to_type.clone())
        }

        (Date64, Int64) => cast_array_data::<Int64Type>(array, to_type.clone()),
        (Date64, Int32) => cast_with_options(
            &cast_with_options(array, &DataType::Int64, &cast_options)?,
            &DataType::Int32,
            &cast_options,
        ),
        (Time64(_), Int64) => cast_array_data::<Int64Type>(array, to_type.clone()),
        (Date32, Date64) => {
            let date_array = array.as_any().downcast_ref::<Date32Array>().unwrap();

            let values =
                unary::<_, _, Date64Type>(date_array, |x| x as i64 * MILLISECONDS_IN_DAY);

            Ok(Arc::new(values) as ArrayRef)
        }
        (Date64, Date32) => {
            let date_array = array.as_any().downcast_ref::<Date64Array>().unwrap();

            let values = unary::<_, _, Date32Type>(date_array, |x| {
                (x / MILLISECONDS_IN_DAY) as i32
            });

            Ok(Arc::new(values) as ArrayRef)
        }
        (Time32(TimeUnit::Second), Time32(TimeUnit::Millisecond)) => {
            let time_array = array.as_any().downcast_ref::<Time32SecondArray>().unwrap();

            let values = unary::<_, _, Time32MillisecondType>(time_array, |x| {
                x * MILLISECONDS as i32
            });

            Ok(Arc::new(values) as ArrayRef)
        }
        (Time32(TimeUnit::Millisecond), Time32(TimeUnit::Second)) => {
            let time_array = array
                .as_any()
                .downcast_ref::<Time32MillisecondArray>()
                .unwrap();

            let values = unary::<_, _, Time32SecondType>(time_array, |x| {
                x / (MILLISECONDS as i32)
            });

            Ok(Arc::new(values) as ArrayRef)
        }
        //(Time32(TimeUnit::Second), Time64(_)) => {},
        (Time32(from_unit), Time64(to_unit)) => {
            let time_array = Int32Array::from(array.data().clone());
            // note: (numeric_cast + SIMD multiply) is faster than (cast & multiply)
            let c: Int64Array = numeric_cast(&time_array);
            let from_size = time_unit_multiple(&from_unit);
            let to_size = time_unit_multiple(&to_unit);
            // from is only smaller than to if 64milli/64second don't exist
            let mult = Int64Array::from(vec![to_size / from_size; array.len()]);
            let converted = multiply(&c, &mult)?;
            let array_ref = Arc::new(converted) as ArrayRef;
            use TimeUnit::*;
            match to_unit {
                Microsecond => cast_array_data::<TimestampMicrosecondType>(
                    &array_ref,
                    to_type.clone(),
                ),
                Nanosecond => cast_array_data::<TimestampNanosecondType>(
                    &array_ref,
                    to_type.clone(),
                ),
                _ => unreachable!("array type not supported"),
            }
        }
        (Time64(TimeUnit::Microsecond), Time64(TimeUnit::Nanosecond)) => {
            let time_array = array
                .as_any()
                .downcast_ref::<Time64MicrosecondArray>()
                .unwrap();

            let values =
                unary::<_, _, Time64NanosecondType>(time_array, |x| x * MILLISECONDS);
            Ok(Arc::new(values) as ArrayRef)
        }
        (Time64(TimeUnit::Nanosecond), Time64(TimeUnit::Microsecond)) => {
            let time_array = array
                .as_any()
                .downcast_ref::<Time64NanosecondArray>()
                .unwrap();

            let values =
                unary::<_, _, Time64MicrosecondType>(time_array, |x| x / MILLISECONDS);
            Ok(Arc::new(values) as ArrayRef)
        }
        (Time64(from_unit), Time32(to_unit)) => {
            let time_array = Int64Array::from(array.data().clone());
            let from_size = time_unit_multiple(&from_unit);
            let to_size = time_unit_multiple(&to_unit);
            let divisor = from_size / to_size;
            match to_unit {
                TimeUnit::Second => {
                    let values = unary::<_, _, Time32SecondType>(&time_array, |x| {
                        (x as i64 / divisor) as i32
                    });
                    Ok(Arc::new(values) as ArrayRef)
                }
                TimeUnit::Millisecond => {
                    let values = unary::<_, _, Time32MillisecondType>(&time_array, |x| {
                        (x as i64 / divisor) as i32
                    });
                    Ok(Arc::new(values) as ArrayRef)
                }
                _ => unreachable!("array type not supported"),
            }
        }
        (Timestamp(_, _), Int64) => cast_array_data::<Int64Type>(array, to_type.clone()),
        (Int64, Timestamp(to_unit, _)) => {
            use TimeUnit::*;
            match to_unit {
                Second => cast_array_data::<TimestampSecondType>(array, to_type.clone()),
                Millisecond => {
                    cast_array_data::<TimestampMillisecondType>(array, to_type.clone())
                }
                Microsecond => {
                    cast_array_data::<TimestampMicrosecondType>(array, to_type.clone())
                }
                Nanosecond => {
                    cast_array_data::<TimestampNanosecondType>(array, to_type.clone())
                }
            }
        }
        (Timestamp(from_unit, _), Timestamp(to_unit, _)) => {
            let time_array = Int64Array::from(array.data().clone());
            let from_size = time_unit_multiple(&from_unit);
            let to_size = time_unit_multiple(&to_unit);
            // we either divide or multiply, depending on size of each unit
            // units are never the same when the types are the same
            let converted = if from_size >= to_size {
                divide(
                    &time_array,
                    &Int64Array::from(vec![from_size / to_size; array.len()]),
                )?
            } else {
                multiply(
                    &time_array,
                    &Int64Array::from(vec![to_size / from_size; array.len()]),
                )?
            };
            let array_ref = Arc::new(converted) as ArrayRef;
            use TimeUnit::*;
            match to_unit {
                Second => {
                    cast_array_data::<TimestampSecondType>(&array_ref, to_type.clone())
                }
                Millisecond => cast_array_data::<TimestampMillisecondType>(
                    &array_ref,
                    to_type.clone(),
                ),
                Microsecond => cast_array_data::<TimestampMicrosecondType>(
                    &array_ref,
                    to_type.clone(),
                ),
                Nanosecond => cast_array_data::<TimestampNanosecondType>(
                    &array_ref,
                    to_type.clone(),
                ),
            }
        }
        (Timestamp(from_unit, _), Date32) => {
            let time_array = Int64Array::from(array.data().clone());
            let from_size = time_unit_multiple(&from_unit) * SECONDS_IN_DAY;
            let mut b = Date32Builder::new(array.len());
            for i in 0..array.len() {
                if array.is_null(i) {
                    b.append_null()?;
                } else {
                    b.append_value((time_array.value(i) / from_size) as i32)?;
                }
            }

            Ok(Arc::new(b.finish()) as ArrayRef)
        }
        (Timestamp(from_unit, _), Date64) => {
            let from_size = time_unit_multiple(&from_unit);
            let to_size = MILLISECONDS;

            // Scale time_array by (to_size / from_size) using a
            // single integer operation, but need to avoid integer
            // math rounding down to zero

            match to_size.cmp(&from_size) {
                std::cmp::Ordering::Less => {
                    let time_array = Date64Array::from(array.data().clone());
                    Ok(Arc::new(divide(
                        &time_array,
                        &Date64Array::from(vec![from_size / to_size; array.len()]),
                    )?) as ArrayRef)
                }
                std::cmp::Ordering::Equal => {
                    cast_array_data::<Date64Type>(array, to_type.clone())
                }
                std::cmp::Ordering::Greater => {
                    let time_array = Date64Array::from(array.data().clone());
                    Ok(Arc::new(multiply(
                        &time_array,
                        &Date64Array::from(vec![to_size / from_size; array.len()]),
                    )?) as ArrayRef)
                }
            }
        }
        // date64 to timestamp might not make sense,
        (Int64, Duration(to_unit)) => {
            use TimeUnit::*;
            match to_unit {
                Second => cast_array_data::<DurationSecondType>(array, to_type.clone()),
                Millisecond => {
                    cast_array_data::<DurationMillisecondType>(array, to_type.clone())
                }
                Microsecond => {
                    cast_array_data::<DurationMicrosecondType>(array, to_type.clone())
                }
                Nanosecond => {
                    cast_array_data::<DurationNanosecondType>(array, to_type.clone())
                }
            }
        }

        // null to primitive/flat types
        (Null, Int32) => Ok(Arc::new(Int32Array::from(vec![None; array.len()]))),

        (_, _) => Err(ArrowError::CastError(format!(
            "Casting from {:?} to {:?} not supported",
            from_type, to_type,
        ))),
    }
}

/// Get the time unit as a multiple of a second
const fn time_unit_multiple(unit: &TimeUnit) -> i64 {
    match unit {
        TimeUnit::Second => 1,
        TimeUnit::Millisecond => MILLISECONDS,
        TimeUnit::Microsecond => MICROSECONDS,
        TimeUnit::Nanosecond => NANOSECONDS,
    }
}

/// Number of seconds in a day
const SECONDS_IN_DAY: i64 = 86_400;
/// Number of milliseconds in a second
const MILLISECONDS: i64 = 1_000;
/// Number of microseconds in a second
const MICROSECONDS: i64 = 1_000_000;
/// Number of nanoseconds in a second
const NANOSECONDS: i64 = 1_000_000_000;
/// Number of milliseconds in a day
const MILLISECONDS_IN_DAY: i64 = SECONDS_IN_DAY * MILLISECONDS;
/// Number of days between 0001-01-01 and 1970-01-01
const EPOCH_DAYS_FROM_CE: i32 = 719_163;

/// Cast an array by changing its array_data type to the desired type
///
/// Arrays should have the same primitive data type, otherwise this should fail.
/// We do not perform this check on primitive data types as we only use this
/// function internally, where it is guaranteed to be infallible.
fn cast_array_data<TO>(array: &ArrayRef, to_type: DataType) -> Result<ArrayRef>
where
    TO: ArrowNumericType,
{
    let data = ArrayData::new(
        to_type,
        array.len(),
        Some(array.null_count()),
        array.data().null_bitmap().clone().map(|bitmap| bitmap.bits),
        array.data().offset(),
        array.data().buffers().to_vec(),
        vec![],
    );
    Ok(Arc::new(PrimitiveArray::<TO>::from(data)) as ArrayRef)
}

/// Convert Array into a PrimitiveArray of type, and apply numeric cast
fn cast_numeric_arrays<FROM, TO>(from: &ArrayRef) -> Result<ArrayRef>
where
    FROM: ArrowNumericType,
    TO: ArrowNumericType,
    FROM::Native: num::NumCast,
    TO::Native: num::NumCast,
{
    Ok(Arc::new(numeric_cast::<FROM, TO>(
        from.as_any()
            .downcast_ref::<PrimitiveArray<FROM>>()
            .unwrap(),
    )))
}

/// Natural cast between numeric types
fn numeric_cast<T, R>(from: &PrimitiveArray<T>) -> PrimitiveArray<R>
where
    T: ArrowNumericType,
    R: ArrowNumericType,
    T::Native: num::NumCast,
    R::Native: num::NumCast,
{
    let iter = from
        .iter()
        .map(|v| v.and_then(num::cast::cast::<T::Native, R::Native>));
    // Soundness:
    //  The iterator is trustedLen because it comes from an `PrimitiveArray`.
    unsafe { PrimitiveArray::<R>::from_trusted_len_iter(iter) }
}

/// Cast timestamp types to Utf8/LargeUtf8
fn cast_timestamp_to_string<T, OffsetSize>(array: &ArrayRef) -> Result<ArrayRef>
where
    T: ArrowTemporalType + ArrowNumericType,
    i64: From<<T as ArrowPrimitiveType>::Native>,
    OffsetSize: StringOffsetSizeTrait,
{
    let array = array.as_any().downcast_ref::<PrimitiveArray<T>>().unwrap();

    Ok(Arc::new(
        (0..array.len())
            .map(|ix| {
                if array.is_null(ix) {
                    None
                } else {
                    array.value_as_datetime(ix).map(|v| v.to_string())
                }
            })
            .collect::<GenericStringArray<OffsetSize>>(),
    ))
}

/// Cast numeric types to Utf8
fn cast_numeric_to_string<FROM, OffsetSize>(array: &ArrayRef) -> Result<ArrayRef>
where
    FROM: ArrowNumericType,
    FROM::Native: lexical_core::ToLexical,
    OffsetSize: StringOffsetSizeTrait,
{
    Ok(Arc::new(numeric_to_string_cast::<FROM, OffsetSize>(
        array
            .as_any()
            .downcast_ref::<PrimitiveArray<FROM>>()
            .unwrap(),
    )))
}

fn numeric_to_string_cast<T, OffsetSize>(
    from: &PrimitiveArray<T>,
) -> GenericStringArray<OffsetSize>
where
    T: ArrowPrimitiveType + ArrowNumericType,
    T::Native: lexical_core::ToLexical,
    OffsetSize: StringOffsetSizeTrait,
{
    from.iter()
        .map(|maybe_value| maybe_value.map(lexical_to_string))
        .collect()
}

/// Cast numeric types to Utf8
fn cast_string_to_numeric<T, Offset: StringOffsetSizeTrait>(
    from: &ArrayRef,
    cast_options: &CastOptions,
) -> Result<ArrayRef>
where
    T: ArrowNumericType,
    <T as ArrowPrimitiveType>::Native: lexical_core::FromLexical,
{
    Ok(Arc::new(string_to_numeric_cast::<T, Offset>(
        from.as_any()
            .downcast_ref::<GenericStringArray<Offset>>()
            .unwrap(),
        cast_options,
    )?))
}

fn string_to_numeric_cast<T, Offset: StringOffsetSizeTrait>(
    from: &GenericStringArray<Offset>,
    cast_options: &CastOptions,
) -> Result<PrimitiveArray<T>>
where
    T: ArrowNumericType,
    <T as ArrowPrimitiveType>::Native: lexical_core::FromLexical,
{
    if cast_options.safe {
        let iter = (0..from.len()).map(|i| {
            if from.is_null(i) {
                None
            } else {
                lexical_core::parse(from.value(i).as_bytes()).ok()
            }
        });
        // Benefit:
        //     20% performance improvement
        // Soundness:
        //     The iterator is trustedLen because it comes from an `StringArray`.
        Ok(unsafe { PrimitiveArray::<T>::from_trusted_len_iter(iter) })
    } else {
        let vec = (0..from.len())
            .map(|i| {
                if from.is_null(i) {
                    Ok(None)
                } else {
                    let string = from.value(i);
                    let result = lexical_core::parse(string.as_bytes());
                    Some(result.map_err(|_| {
                        ArrowError::CastError(format!(
                            "Cannot cast string '{}' to value of {} type",
                            string,
                            std::any::type_name::<T>()
                        ))
                    }))
                    .transpose()
                }
            })
            .collect::<Result<Vec<_>>>()?;
        // Benefit:
        //     20% performance improvement
        // Soundness:
        //     The iterator is trustedLen because it comes from an `StringArray`.
        Ok(unsafe { PrimitiveArray::<T>::from_trusted_len_iter(vec.iter()) })
    }
}

/// Casts generic string arrays to Date32Array
fn cast_string_to_date32<Offset: StringOffsetSizeTrait>(
    array: &dyn Array,
    cast_options: &CastOptions,
) -> Result<ArrayRef> {
    use chrono::Datelike;
    let string_array = array
        .as_any()
        .downcast_ref::<GenericStringArray<Offset>>()
        .unwrap();

    let array = if cast_options.safe {
        let iter = (0..string_array.len()).map(|i| {
            if string_array.is_null(i) {
                None
            } else {
                string_array
                    .value(i)
                    .parse::<chrono::NaiveDate>()
                    .map(|date| date.num_days_from_ce() - EPOCH_DAYS_FROM_CE)
                    .ok()
            }
        });

        // Benefit:
        //     20% performance improvement
        // Soundness:
        //     The iterator is trustedLen because it comes from an `StringArray`.
        unsafe { Date32Array::from_trusted_len_iter(iter) }
    } else {
        let vec = (0..string_array.len())
            .map(|i| {
                if string_array.is_null(i) {
                    Ok(None)
                } else {
                    let string = string_array
                        .value(i);

                    let result = string
                        .parse::<chrono::NaiveDate>()
                        .map(|date| date.num_days_from_ce() - EPOCH_DAYS_FROM_CE);

                    Some(result.map_err(|_| {
                        ArrowError::CastError(
                            format!("Cannot cast string '{}' to value of arrow::datatypes::types::Date32Type type", string),
                        )
                    }))
                        .transpose()
                }
            })
            .collect::<Result<Vec<Option<i32>>>>()?;

        // Benefit:
        //     20% performance improvement
        // Soundness:
        //     The iterator is trustedLen because it comes from an `StringArray`.
        unsafe { Date32Array::from_trusted_len_iter(vec.iter()) }
    };

    Ok(Arc::new(array) as ArrayRef)
}

/// Casts generic string arrays to Date64Array
fn cast_string_to_date64<Offset: StringOffsetSizeTrait>(
    array: &dyn Array,
    cast_options: &CastOptions,
) -> Result<ArrayRef> {
    let string_array = array
        .as_any()
        .downcast_ref::<GenericStringArray<Offset>>()
        .unwrap();

    let array = if cast_options.safe {
        let iter = (0..string_array.len()).map(|i| {
            if string_array.is_null(i) {
                None
            } else {
                string_array
                    .value(i)
                    .parse::<chrono::NaiveDateTime>()
                    .map(|datetime| datetime.timestamp_millis())
                    .ok()
            }
        });

        // Benefit:
        //     20% performance improvement
        // Soundness:
        //     The iterator is trustedLen because it comes from an `StringArray`.
        unsafe { Date64Array::from_trusted_len_iter(iter) }
    } else {
        let vec = (0..string_array.len())
            .map(|i| {
                if string_array.is_null(i) {
                    Ok(None)
                } else {
                let string = string_array
                        .value(i);

                    let result = string
                        .parse::<chrono::NaiveDateTime>()
                        .map(|datetime| datetime.timestamp_millis());

                    Some(result.map_err(|_| {
                        ArrowError::CastError(
                            format!("Cannot cast string '{}' to value of arrow::datatypes::types::Date64Type type", string),
                        )
                    }))
                        .transpose()
                }
            })
            .collect::<Result<Vec<Option<i64>>>>()?;

        // Benefit:
        //     20% performance improvement
        // Soundness:
        //     The iterator is trustedLen because it comes from an `StringArray`.
        unsafe { Date64Array::from_trusted_len_iter(vec.iter()) }
    };

    Ok(Arc::new(array) as ArrayRef)
}

/// Casts generic string arrays to TimeStampNanosecondArray
fn cast_string_to_timestamp_ns<Offset: StringOffsetSizeTrait>(
    array: &dyn Array,
    cast_options: &CastOptions,
) -> Result<ArrayRef> {
    let string_array = array
        .as_any()
        .downcast_ref::<GenericStringArray<Offset>>()
        .unwrap();

    let array = if cast_options.safe {
        let iter = (0..string_array.len()).map(|i| {
            if string_array.is_null(i) {
                None
            } else {
                string_to_timestamp_nanos(string_array.value(i)).ok()
            }
        });
        // Benefit:
        //     20% performance improvement
        // Soundness:
        //     The iterator is trustedLen because it comes from an `StringArray`.
        unsafe { TimestampNanosecondArray::from_trusted_len_iter(iter) }
    } else {
        let vec = (0..string_array.len())
            .map(|i| {
                if string_array.is_null(i) {
                    Ok(None)
                } else {
                    let result = string_to_timestamp_nanos(string_array.value(i));
                    Some(result).transpose()
                }
            })
            .collect::<Result<Vec<Option<i64>>>>()?;

        // Benefit:
        //     20% performance improvement
        // Soundness:
        //     The iterator is trustedLen because it comes from an `StringArray`.
        unsafe { TimestampNanosecondArray::from_trusted_len_iter(vec.iter()) }
    };

    Ok(Arc::new(array) as ArrayRef)
}

/// Cast numeric types to Boolean
///
/// Any zero value returns `false` while non-zero returns `true`
fn cast_numeric_to_bool<FROM>(from: &ArrayRef) -> Result<ArrayRef>
where
    FROM: ArrowNumericType,
{
    numeric_to_bool_cast::<FROM>(
        from.as_any()
            .downcast_ref::<PrimitiveArray<FROM>>()
            .unwrap(),
    )
    .map(|to| Arc::new(to) as ArrayRef)
}

fn numeric_to_bool_cast<T>(from: &PrimitiveArray<T>) -> Result<BooleanArray>
where
    T: ArrowPrimitiveType + ArrowNumericType,
{
    let mut b = BooleanBuilder::new(from.len());

    for i in 0..from.len() {
        if from.is_null(i) {
            b.append_null()?;
        } else if from.value(i) != T::default_value() {
            b.append_value(true)?;
        } else {
            b.append_value(false)?;
        }
    }

    Ok(b.finish())
}

/// Cast Boolean types to numeric
///
/// `false` returns 0 while `true` returns 1
fn cast_bool_to_numeric<TO>(
    from: &ArrayRef,
    cast_options: &CastOptions,
) -> Result<ArrayRef>
where
    TO: ArrowNumericType,
    TO::Native: num::cast::NumCast,
{
    Ok(Arc::new(bool_to_numeric_cast::<TO>(
        from.as_any().downcast_ref::<BooleanArray>().unwrap(),
        cast_options,
    )))
}

fn bool_to_numeric_cast<T>(
    from: &BooleanArray,
    _cast_options: &CastOptions,
) -> PrimitiveArray<T>
where
    T: ArrowNumericType,
    T::Native: num::NumCast,
{
    let iter = (0..from.len()).map(|i| {
        if from.is_null(i) {
            None
        } else if from.value(i) {
            // a workaround to cast a primitive to T::Native, infallible
            num::cast::cast(1)
        } else {
            Some(T::default_value())
        }
    });
    // Benefit:
    //     20% performance improvement
    // Soundness:
    //     The iterator is trustedLen because it comes from a Range
    unsafe { PrimitiveArray::<T>::from_trusted_len_iter(iter) }
}

/// Attempts to cast an `ArrayDictionary` with index type K into
/// `to_type` for supported types.
///
/// K is the key type
fn dictionary_cast<K: ArrowDictionaryKeyType>(
    array: &ArrayRef,
    to_type: &DataType,
    cast_options: &CastOptions,
) -> Result<ArrayRef> {
    use DataType::*;

    match to_type {
        Dictionary(to_index_type, to_value_type) => {
            let dict_array = array
                .as_any()
                .downcast_ref::<DictionaryArray<K>>()
                .ok_or_else(|| {
                    ArrowError::ComputeError(
                        "Internal Error: Cannot cast dictionary to DictionaryArray of expected type".to_string(),
                    )
                })?;

            let keys_array: ArrayRef =
                Arc::new(PrimitiveArray::<K>::from(dict_array.keys().data().clone()));
            let values_array = dict_array.values();
            let cast_keys = cast_with_options(&keys_array, to_index_type, &cast_options)?;
            let cast_values =
                cast_with_options(values_array, to_value_type, &cast_options)?;

            // Failure to cast keys (because they don't fit in the
            // target type) results in NULL values;
            if cast_keys.null_count() > keys_array.null_count() {
                return Err(ArrowError::ComputeError(format!(
                    "Could not convert {} dictionary indexes from {:?} to {:?}",
                    cast_keys.null_count() - keys_array.null_count(),
                    keys_array.data_type(),
                    to_index_type
                )));
            }

            // keys are data, child_data is values (dictionary)
            let data = ArrayData::new(
                to_type.clone(),
                cast_keys.len(),
                Some(cast_keys.null_count()),
                cast_keys
                    .data()
                    .null_bitmap()
                    .clone()
                    .map(|bitmap| bitmap.bits),
                cast_keys.data().offset(),
                cast_keys.data().buffers().to_vec(),
                vec![cast_values.data().clone()],
            );

            // create the appropriate array type
            let new_array: ArrayRef = match **to_index_type {
                Int8 => Arc::new(DictionaryArray::<Int8Type>::from(data)),
                Int16 => Arc::new(DictionaryArray::<Int16Type>::from(data)),
                Int32 => Arc::new(DictionaryArray::<Int32Type>::from(data)),
                Int64 => Arc::new(DictionaryArray::<Int64Type>::from(data)),
                UInt8 => Arc::new(DictionaryArray::<UInt8Type>::from(data)),
                UInt16 => Arc::new(DictionaryArray::<UInt16Type>::from(data)),
                UInt32 => Arc::new(DictionaryArray::<UInt32Type>::from(data)),
                UInt64 => Arc::new(DictionaryArray::<UInt64Type>::from(data)),
                _ => {
                    return Err(ArrowError::CastError(format!(
                        "Unsupported type {:?} for dictionary index",
                        to_index_type
                    )))
                }
            };

            Ok(new_array)
        }
        _ => unpack_dictionary::<K>(array, to_type, cast_options),
    }
}

// Unpack a dictionary where the keys are of type <K> into a flattened array of type to_type
fn unpack_dictionary<K>(
    array: &ArrayRef,
    to_type: &DataType,
    cast_options: &CastOptions,
) -> Result<ArrayRef>
where
    K: ArrowDictionaryKeyType,
{
    let dict_array = array
        .as_any()
        .downcast_ref::<DictionaryArray<K>>()
        .ok_or_else(|| {
            ArrowError::ComputeError(
                "Internal Error: Cannot cast dictionary to DictionaryArray of expected type".to_string(),
            )
        })?;

    // attempt to cast the dict values to the target type
    // use the take kernel to expand out the dictionary
    let cast_dict_values =
        cast_with_options(&dict_array.values(), to_type, cast_options)?;

    // Note take requires first casting the indices to u32
    let keys_array: ArrayRef =
        Arc::new(PrimitiveArray::<K>::from(dict_array.keys().data().clone()));
    let indicies = cast_with_options(&keys_array, &DataType::UInt32, cast_options)?;
    let u32_indicies =
        indicies
            .as_any()
            .downcast_ref::<UInt32Array>()
            .ok_or_else(|| {
                ArrowError::ComputeError(
                    "Internal Error: Cannot cast dict indices to UInt32".to_string(),
                )
            })?;

    take(cast_dict_values.as_ref(), u32_indicies, None)
}

/// Attempts to encode an array into an `ArrayDictionary` with index
/// type K and value (dictionary) type value_type
///
/// K is the key type
fn cast_to_dictionary<K: ArrowDictionaryKeyType>(
    array: &ArrayRef,
    dict_value_type: &DataType,
    cast_options: &CastOptions,
) -> Result<ArrayRef> {
    use DataType::*;

    match *dict_value_type {
        Int8 => pack_numeric_to_dictionary::<K, Int8Type>(
            array,
            dict_value_type,
            cast_options,
        ),
        Int16 => pack_numeric_to_dictionary::<K, Int16Type>(
            array,
            dict_value_type,
            cast_options,
        ),
        Int32 => pack_numeric_to_dictionary::<K, Int32Type>(
            array,
            dict_value_type,
            cast_options,
        ),
        Int64 => pack_numeric_to_dictionary::<K, Int64Type>(
            array,
            dict_value_type,
            cast_options,
        ),
        UInt8 => pack_numeric_to_dictionary::<K, UInt8Type>(
            array,
            dict_value_type,
            cast_options,
        ),
        UInt16 => pack_numeric_to_dictionary::<K, UInt16Type>(
            array,
            dict_value_type,
            cast_options,
        ),
        UInt32 => pack_numeric_to_dictionary::<K, UInt32Type>(
            array,
            dict_value_type,
            cast_options,
        ),
        UInt64 => pack_numeric_to_dictionary::<K, UInt64Type>(
            array,
            dict_value_type,
            cast_options,
        ),
        Utf8 => pack_string_to_dictionary::<K>(array, cast_options),
        _ => Err(ArrowError::CastError(format!(
            "Unsupported output type for dictionary packing: {:?}",
            dict_value_type
        ))),
    }
}

// Packs the data from the primitive array of type <V> to a
// DictionaryArray with keys of type K and values of value_type V
fn pack_numeric_to_dictionary<K, V>(
    array: &ArrayRef,
    dict_value_type: &DataType,
    cast_options: &CastOptions,
) -> Result<ArrayRef>
where
    K: ArrowDictionaryKeyType,
    V: ArrowNumericType,
{
    // attempt to cast the source array values to the target value type (the dictionary values type)
    let cast_values = cast_with_options(array, &dict_value_type, cast_options)?;
    let values = cast_values
        .as_any()
        .downcast_ref::<PrimitiveArray<V>>()
        .unwrap();

    let keys_builder = PrimitiveBuilder::<K>::new(values.len());
    let values_builder = PrimitiveBuilder::<V>::new(values.len());
    let mut b = PrimitiveDictionaryBuilder::new(keys_builder, values_builder);

    // copy each element one at a time
    for i in 0..values.len() {
        if values.is_null(i) {
            b.append_null()?;
        } else {
            b.append(values.value(i))?;
        }
    }
    Ok(Arc::new(b.finish()))
}

// Packs the data as a StringDictionaryArray, if possible, with the
// key types of K
fn pack_string_to_dictionary<K>(
    array: &ArrayRef,
    cast_options: &CastOptions,
) -> Result<ArrayRef>
where
    K: ArrowDictionaryKeyType,
{
    let cast_values = cast_with_options(array, &DataType::Utf8, cast_options)?;
    let values = cast_values.as_any().downcast_ref::<StringArray>().unwrap();

    let keys_builder = PrimitiveBuilder::<K>::new(values.len());
    let values_builder = StringBuilder::new(values.len());
    let mut b = StringDictionaryBuilder::new(keys_builder, values_builder);

    // copy each element one at a time
    for i in 0..values.len() {
        if values.is_null(i) {
            b.append_null()?;
        } else {
            b.append(values.value(i))?;
        }
    }
    Ok(Arc::new(b.finish()))
}

/// Helper function that takes a primitive array and casts to a (generic) list array.
fn cast_primitive_to_list<OffsetSize: OffsetSizeTrait + NumCast>(
    array: &ArrayRef,
    to: &Field,
    to_type: &DataType,
    cast_options: &CastOptions,
) -> Result<ArrayRef> {
    // cast primitive to list's primitive
    let cast_array = cast_with_options(array, to.data_type(), cast_options)?;
    // create offsets, where if array.len() = 2, we have [0,1,2]
    // Safety:
    // Length of range can be trusted.
    // Note: could not yet create a generic range in stable Rust.
    let offsets = unsafe {
        MutableBuffer::from_trusted_len_iter(
            (0..=array.len()).map(|i| OffsetSize::from(i).expect("integer")),
        )
    };

    let list_data = ArrayData::new(
        to_type.clone(),
        array.len(),
        Some(cast_array.null_count()),
        cast_array
            .data()
            .null_bitmap()
            .clone()
            .map(|bitmap| bitmap.bits),
        0,
        vec![offsets.into()],
        vec![cast_array.data().clone()],
    );
    let list_array =
        Arc::new(GenericListArray::<OffsetSize>::from(list_data)) as ArrayRef;

    Ok(list_array)
}

/// Helper function that takes an Generic list container and casts the inner datatype.
fn cast_list_inner<OffsetSize: OffsetSizeTrait>(
    array: &Arc<dyn Array>,
    to: &Field,
    to_type: &DataType,
    cast_options: &CastOptions,
) -> Result<ArrayRef> {
    let data = array.data_ref();
    let underlying_array = make_array(data.child_data()[0].clone());
    let cast_array = cast_with_options(&underlying_array, to.data_type(), cast_options)?;
    let array_data = ArrayData::new(
        to_type.clone(),
        array.len(),
        Some(cast_array.null_count()),
        cast_array
            .data()
            .null_bitmap()
            .clone()
            .map(|bitmap| bitmap.bits),
        array.offset(),
        // reuse offset buffer
        data.buffers().to_vec(),
        vec![cast_array.data().clone()],
    );
    let list = GenericListArray::<OffsetSize>::from(array_data);
    Ok(Arc::new(list) as ArrayRef)
}

/// Helper function to cast from `Utf8` to `LargeUtf8` and vice versa. If the `LargeUtf8` is too large for
/// a `Utf8` array it will return an Error.
fn cast_str_container<OffsetSizeFrom, OffsetSizeTo>(array: &dyn Array) -> Result<ArrayRef>
where
    OffsetSizeFrom: StringOffsetSizeTrait + ToPrimitive,
    OffsetSizeTo: StringOffsetSizeTrait + NumCast + ArrowNativeType,
{
    let str_array = array
        .as_any()
        .downcast_ref::<GenericStringArray<OffsetSizeFrom>>()
        .unwrap();
    let list_data = array.data();
    let str_values_buf = str_array.value_data();

    let offsets = unsafe { list_data.buffers()[0].typed_data::<OffsetSizeFrom>() };

    let mut offset_builder = BufferBuilder::<OffsetSizeTo>::new(offsets.len());
    offsets.iter().try_for_each::<_, Result<_>>(|offset| {
        let offset = OffsetSizeTo::from(*offset).ok_or_else(|| {
            ArrowError::ComputeError(
                "large-utf8 array too large to cast to utf8-array".into(),
            )
        })?;
        offset_builder.append(offset);
        Ok(())
    })?;

    let offset_buffer = offset_builder.finish();

    let dtype = if matches!(std::mem::size_of::<OffsetSizeTo>(), 8) {
        DataType::LargeUtf8
    } else {
        DataType::Utf8
    };

    let mut builder = ArrayData::builder(dtype)
        .offset(array.offset())
        .len(array.len())
        .add_buffer(offset_buffer)
        .add_buffer(str_values_buf);

    if let Some(buf) = list_data.null_buffer() {
        builder = builder.null_bit_buffer(buf.clone())
    }
    let data = builder.build();
    Ok(Arc::new(GenericStringArray::<OffsetSizeTo>::from(data)))
}

/// Cast the container type of List/Largelist array but not the inner types.
/// This function can leave the value data intact and only has to cast the offset dtypes.
fn cast_list_container<OffsetSizeFrom, OffsetSizeTo>(
    array: &dyn Array,
    _cast_options: &CastOptions,
) -> Result<ArrayRef>
where
    OffsetSizeFrom: OffsetSizeTrait + ToPrimitive,
    OffsetSizeTo: OffsetSizeTrait + NumCast,
{
    let data = array.data_ref();
    // the value data stored by the list
    let value_data = data.child_data()[0].clone();

    let out_dtype = match array.data_type() {
        DataType::List(value_type) => {
            assert_eq!(
                std::mem::size_of::<OffsetSizeFrom>(),
                std::mem::size_of::<i32>()
            );
            assert_eq!(
                std::mem::size_of::<OffsetSizeTo>(),
                std::mem::size_of::<i64>()
            );
            DataType::LargeList(value_type.clone())
        }
        DataType::LargeList(value_type) => {
            assert_eq!(
                std::mem::size_of::<OffsetSizeFrom>(),
                std::mem::size_of::<i64>()
            );
            assert_eq!(
                std::mem::size_of::<OffsetSizeTo>(),
                std::mem::size_of::<i32>()
            );
            if value_data.len() > i32::MAX as usize {
                return Err(ArrowError::ComputeError(
                    "LargeList too large to cast to List".into(),
                ));
            }
            DataType::List(value_type.clone())
        }
        // implementation error
        _ => unreachable!(),
    };

    // Safety:
    //      The first buffer is the offsets and they are aligned to OffSetSizeFrom: (i64 or i32)
    // Justification:
    //      The safe variant data.buffer::<OffsetSizeFrom> take the offset into account and we
    //      cannot create a list array with offsets starting at non zero.
    let offsets = unsafe { data.buffers()[0].as_slice().align_to::<OffsetSizeFrom>() }.1;

    let iter = offsets.iter().map(|idx| {
        let idx: OffsetSizeTo = NumCast::from(*idx).unwrap();
        idx
    });

    // SAFETY
    //      A slice produces a trusted length iterator
    let offset_buffer = unsafe { Buffer::from_trusted_len_iter(iter) };

    // wrap up
    let mut builder = ArrayData::builder(out_dtype)
        .offset(array.offset())
        .len(array.len())
        .add_buffer(offset_buffer)
        .add_child_data(value_data);

    if let Some(buf) = data.null_buffer() {
        builder = builder.null_bit_buffer(buf.clone())
    }
    let data = builder.build();
    Ok(make_array(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{buffer::Buffer, util::display::array_value_to_string};

    #[test]
    fn test_cast_i32_to_f64() {
        let a = Int32Array::from(vec![5, 6, 7, 8, 9]);
        let array = Arc::new(a) as ArrayRef;
        let b = cast(&array, &DataType::Float64).unwrap();
        let c = b.as_any().downcast_ref::<Float64Array>().unwrap();
        assert!(5.0 - c.value(0) < f64::EPSILON);
        assert!(6.0 - c.value(1) < f64::EPSILON);
        assert!(7.0 - c.value(2) < f64::EPSILON);
        assert!(8.0 - c.value(3) < f64::EPSILON);
        assert!(9.0 - c.value(4) < f64::EPSILON);
    }

    #[test]
    fn test_cast_i32_to_u8() {
        let a = Int32Array::from(vec![-5, 6, -7, 8, 100000000]);
        let array = Arc::new(a) as ArrayRef;
        let b = cast(&array, &DataType::UInt8).unwrap();
        let c = b.as_any().downcast_ref::<UInt8Array>().unwrap();
        assert!(!c.is_valid(0));
        assert_eq!(6, c.value(1));
        assert!(!c.is_valid(2));
        assert_eq!(8, c.value(3));
        // overflows return None
        assert!(!c.is_valid(4));
    }

    #[test]
    fn test_cast_i32_to_u8_sliced() {
        let a = Int32Array::from(vec![-5, 6, -7, 8, 100000000]);
        let array = Arc::new(a) as ArrayRef;
        assert_eq!(0, array.offset());
        let array = array.slice(2, 3);
        assert_eq!(2, array.offset());
        let b = cast(&array, &DataType::UInt8).unwrap();
        assert_eq!(3, b.len());
        assert_eq!(0, b.offset());
        let c = b.as_any().downcast_ref::<UInt8Array>().unwrap();
        assert!(!c.is_valid(0));
        assert_eq!(8, c.value(1));
        // overflows return None
        assert!(!c.is_valid(2));
    }

    #[test]
    fn test_cast_i32_to_i32() {
        let a = Int32Array::from(vec![5, 6, 7, 8, 9]);
        let array = Arc::new(a) as ArrayRef;
        let b = cast(&array, &DataType::Int32).unwrap();
        let c = b.as_any().downcast_ref::<Int32Array>().unwrap();
        assert_eq!(5, c.value(0));
        assert_eq!(6, c.value(1));
        assert_eq!(7, c.value(2));
        assert_eq!(8, c.value(3));
        assert_eq!(9, c.value(4));
    }

    #[test]
    fn test_cast_i32_to_list_i32() {
        let a = Int32Array::from(vec![5, 6, 7, 8, 9]);
        let array = Arc::new(a) as ArrayRef;
        let b = cast(
            &array,
            &DataType::List(Box::new(Field::new("item", DataType::Int32, true))),
        )
        .unwrap();
        assert_eq!(5, b.len());
        let arr = b.as_any().downcast_ref::<ListArray>().unwrap();
        assert_eq!(&[0, 1, 2, 3, 4, 5], arr.value_offsets());
        assert_eq!(1, arr.value_length(0));
        assert_eq!(1, arr.value_length(1));
        assert_eq!(1, arr.value_length(2));
        assert_eq!(1, arr.value_length(3));
        assert_eq!(1, arr.value_length(4));
        let values = arr.values();
        let c = values.as_any().downcast_ref::<Int32Array>().unwrap();
        assert_eq!(5, c.value(0));
        assert_eq!(6, c.value(1));
        assert_eq!(7, c.value(2));
        assert_eq!(8, c.value(3));
        assert_eq!(9, c.value(4));
    }

    #[test]
    fn test_cast_i32_to_list_i32_nullable() {
        let a = Int32Array::from(vec![Some(5), None, Some(7), Some(8), Some(9)]);
        let array = Arc::new(a) as ArrayRef;
        let b = cast(
            &array,
            &DataType::List(Box::new(Field::new("item", DataType::Int32, true))),
        )
        .unwrap();
        assert_eq!(5, b.len());
        assert_eq!(1, b.null_count());
        let arr = b.as_any().downcast_ref::<ListArray>().unwrap();
        assert_eq!(&[0, 1, 2, 3, 4, 5], arr.value_offsets());
        assert_eq!(1, arr.value_length(0));
        assert_eq!(1, arr.value_length(1));
        assert_eq!(1, arr.value_length(2));
        assert_eq!(1, arr.value_length(3));
        assert_eq!(1, arr.value_length(4));
        let values = arr.values();
        let c = values.as_any().downcast_ref::<Int32Array>().unwrap();
        assert_eq!(1, c.null_count());
        assert_eq!(5, c.value(0));
        assert!(!c.is_valid(1));
        assert_eq!(7, c.value(2));
        assert_eq!(8, c.value(3));
        assert_eq!(9, c.value(4));
    }

    #[test]
    fn test_cast_i32_to_list_f64_nullable_sliced() {
        let a = Int32Array::from(vec![Some(5), None, Some(7), Some(8), None, Some(10)]);
        let array = Arc::new(a) as ArrayRef;
        let array = array.slice(2, 4);
        let b = cast(
            &array,
            &DataType::List(Box::new(Field::new("item", DataType::Float64, true))),
        )
        .unwrap();
        assert_eq!(4, b.len());
        assert_eq!(1, b.null_count());
        let arr = b.as_any().downcast_ref::<ListArray>().unwrap();
        assert_eq!(&[0, 1, 2, 3, 4], arr.value_offsets());
        assert_eq!(1, arr.value_length(0));
        assert_eq!(1, arr.value_length(1));
        assert_eq!(1, arr.value_length(2));
        assert_eq!(1, arr.value_length(3));
        let values = arr.values();
        let c = values.as_any().downcast_ref::<Float64Array>().unwrap();
        assert_eq!(1, c.null_count());
        assert!(7.0 - c.value(0) < f64::EPSILON);
        assert!(8.0 - c.value(1) < f64::EPSILON);
        assert!(!c.is_valid(2));
        assert!(10.0 - c.value(3) < f64::EPSILON);
    }

    #[test]
    fn test_cast_utf8_to_i32() {
        let a = StringArray::from(vec!["5", "6", "seven", "8", "9.1"]);
        let array = Arc::new(a) as ArrayRef;
        let b = cast(&array, &DataType::Int32).unwrap();
        let c = b.as_any().downcast_ref::<Int32Array>().unwrap();
        assert_eq!(5, c.value(0));
        assert_eq!(6, c.value(1));
        assert!(!c.is_valid(2));
        assert_eq!(8, c.value(3));
        assert!(!c.is_valid(4));
    }

    #[test]
    fn test_cast_with_options_utf8_to_i32() {
        let a = StringArray::from(vec!["5", "6", "seven", "8", "9.1"]);
        let array = Arc::new(a) as ArrayRef;
        let result =
            cast_with_options(&array, &DataType::Int32, &CastOptions { safe: false });
        match result {
            Ok(_) => panic!("expected error"),
            Err(e) => {
                assert!(e.to_string().contains(
                    "Cast error: Cannot cast string 'seven' to value of arrow::datatypes::types::Int32Type type"
                ))
            }
        }
    }

    #[test]
    fn test_cast_bool_to_i32() {
        let a = BooleanArray::from(vec![Some(true), Some(false), None]);
        let array = Arc::new(a) as ArrayRef;
        let b = cast(&array, &DataType::Int32).unwrap();
        let c = b.as_any().downcast_ref::<Int32Array>().unwrap();
        assert_eq!(1, c.value(0));
        assert_eq!(0, c.value(1));
        assert!(!c.is_valid(2));
    }

    #[test]
    fn test_cast_bool_to_f64() {
        let a = BooleanArray::from(vec![Some(true), Some(false), None]);
        let array = Arc::new(a) as ArrayRef;
        let b = cast(&array, &DataType::Float64).unwrap();
        let c = b.as_any().downcast_ref::<Float64Array>().unwrap();
        assert!(1.0 - c.value(0) < f64::EPSILON);
        assert!(0.0 - c.value(1) < f64::EPSILON);
        assert!(!c.is_valid(2));
    }

    #[test]
    #[should_panic(
        expected = "Casting from Int32 to Timestamp(Microsecond, None) not supported"
    )]
    fn test_cast_int32_to_timestamp() {
        let a = Int32Array::from(vec![Some(2), Some(10), None]);
        let array = Arc::new(a) as ArrayRef;
        cast(&array, &DataType::Timestamp(TimeUnit::Microsecond, None)).unwrap();
    }

    #[test]
    fn test_cast_list_i32_to_list_u16() {
        // Construct a value array
        let value_data = Int32Array::from(vec![0, 0, 0, -1, -2, -1, 2, 100000000])
            .data()
            .clone();

        let value_offsets = Buffer::from_slice_ref(&[0, 3, 6, 8]);

        // Construct a list array from the above two
        let list_data_type =
            DataType::List(Box::new(Field::new("item", DataType::Int32, true)));
        let list_data = ArrayData::builder(list_data_type)
            .len(3)
            .add_buffer(value_offsets)
            .add_child_data(value_data)
            .build();
        let list_array = Arc::new(ListArray::from(list_data)) as ArrayRef;

        let cast_array = cast(
            &list_array,
            &DataType::List(Box::new(Field::new("item", DataType::UInt16, true))),
        )
        .unwrap();
        // 3 negative values should get lost when casting to unsigned,
        // 1 value should overflow
        assert_eq!(4, cast_array.null_count());
        // offsets should be the same
        assert_eq!(
            list_array.data().buffers().to_vec(),
            cast_array.data().buffers().to_vec()
        );
        let array = cast_array
            .as_ref()
            .as_any()
            .downcast_ref::<ListArray>()
            .unwrap();
        assert_eq!(DataType::UInt16, array.value_type());
        assert_eq!(4, array.values().null_count());
        assert_eq!(3, array.value_length(0));
        assert_eq!(3, array.value_length(1));
        assert_eq!(2, array.value_length(2));
        let values = array.values();
        let u16arr = values.as_any().downcast_ref::<UInt16Array>().unwrap();
        assert_eq!(8, u16arr.len());
        assert_eq!(4, u16arr.null_count());

        assert_eq!(0, u16arr.value(0));
        assert_eq!(0, u16arr.value(1));
        assert_eq!(0, u16arr.value(2));
        assert!(!u16arr.is_valid(3));
        assert!(!u16arr.is_valid(4));
        assert!(!u16arr.is_valid(5));
        assert_eq!(2, u16arr.value(6));
        assert!(!u16arr.is_valid(7));
    }

    #[test]
    #[should_panic(
        expected = "Casting from Int32 to Timestamp(Microsecond, None) not supported"
    )]
    fn test_cast_list_i32_to_list_timestamp() {
        // Construct a value array
        let value_data = Int32Array::from(vec![0, 0, 0, -1, -2, -1, 2, 8, 100000000])
            .data()
            .clone();

        let value_offsets = Buffer::from_slice_ref(&[0, 3, 6, 9]);

        // Construct a list array from the above two
        let list_data_type =
            DataType::List(Box::new(Field::new("item", DataType::Int32, true)));
        let list_data = ArrayData::builder(list_data_type)
            .len(3)
            .add_buffer(value_offsets)
            .add_child_data(value_data)
            .build();
        let list_array = Arc::new(ListArray::from(list_data)) as ArrayRef;

        cast(
            &list_array,
            &DataType::List(Box::new(Field::new(
                "item",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                true,
            ))),
        )
        .unwrap();
    }

    #[test]
    fn test_cast_date32_to_date64() {
        let a = Date32Array::from(vec![10000, 17890]);
        let array = Arc::new(a) as ArrayRef;
        let b = cast(&array, &DataType::Date64).unwrap();
        let c = b.as_any().downcast_ref::<Date64Array>().unwrap();
        assert_eq!(864000000000, c.value(0));
        assert_eq!(1545696000000, c.value(1));
    }

    #[test]
    fn test_cast_date64_to_date32() {
        let a = Date64Array::from(vec![Some(864000000005), Some(1545696000001), None]);
        let array = Arc::new(a) as ArrayRef;
        let b = cast(&array, &DataType::Date32).unwrap();
        let c = b.as_any().downcast_ref::<Date32Array>().unwrap();
        assert_eq!(10000, c.value(0));
        assert_eq!(17890, c.value(1));
        assert!(c.is_null(2));
    }

    #[test]
    fn test_cast_string_to_timestamp() {
        let a1 = Arc::new(StringArray::from(vec![
            Some("2020-09-08T12:00:00+00:00"),
            Some("Not a valid date"),
            None,
        ])) as ArrayRef;
        let a2 = Arc::new(LargeStringArray::from(vec![
            Some("2020-09-08T12:00:00+00:00"),
            Some("Not a valid date"),
            None,
        ])) as ArrayRef;
        for array in &[a1, a2] {
            let b =
                cast(array, &DataType::Timestamp(TimeUnit::Nanosecond, None)).unwrap();
            let c = b
                .as_any()
                .downcast_ref::<TimestampNanosecondArray>()
                .unwrap();
            assert_eq!(1599566400000000000, c.value(0));
            assert!(c.is_null(1));
            assert!(c.is_null(2));
        }
    }

    #[test]
    fn test_cast_date32_to_int32() {
        let a = Date32Array::from(vec![10000, 17890]);
        let array = Arc::new(a) as ArrayRef;
        let b = cast(&array, &DataType::Int32).unwrap();
        let c = b.as_any().downcast_ref::<Int32Array>().unwrap();
        assert_eq!(10000, c.value(0));
        assert_eq!(17890, c.value(1));
    }

    #[test]
    fn test_cast_int32_to_date32() {
        let a = Int32Array::from(vec![10000, 17890]);
        let array = Arc::new(a) as ArrayRef;
        let b = cast(&array, &DataType::Date32).unwrap();
        let c = b.as_any().downcast_ref::<Date32Array>().unwrap();
        assert_eq!(10000, c.value(0));
        assert_eq!(17890, c.value(1));
    }

    #[test]
    fn test_cast_timestamp_to_date32() {
        let a = TimestampMillisecondArray::from_opt_vec(
            vec![Some(864000000005), Some(1545696000001), None],
            Some(String::from("UTC")),
        );
        let array = Arc::new(a) as ArrayRef;
        let b = cast(&array, &DataType::Date32).unwrap();
        let c = b.as_any().downcast_ref::<Date32Array>().unwrap();
        assert_eq!(10000, c.value(0));
        assert_eq!(17890, c.value(1));
        assert!(c.is_null(2));
    }

    #[test]
    fn test_cast_timestamp_to_date64() {
        let a = TimestampMillisecondArray::from_opt_vec(
            vec![Some(864000000005), Some(1545696000001), None],
            None,
        );
        let array = Arc::new(a) as ArrayRef;
        let b = cast(&array, &DataType::Date64).unwrap();
        let c = b.as_any().downcast_ref::<Date64Array>().unwrap();
        assert_eq!(864000000005, c.value(0));
        assert_eq!(1545696000001, c.value(1));
        assert!(c.is_null(2));
    }

    #[test]
    fn test_cast_timestamp_to_i64() {
        let a = TimestampMillisecondArray::from_opt_vec(
            vec![Some(864000000005), Some(1545696000001), None],
            Some("UTC".to_string()),
        );
        let array = Arc::new(a) as ArrayRef;
        let b = cast(&array, &DataType::Int64).unwrap();
        let c = b.as_any().downcast_ref::<Int64Array>().unwrap();
        assert_eq!(&DataType::Int64, c.data_type());
        assert_eq!(864000000005, c.value(0));
        assert_eq!(1545696000001, c.value(1));
        assert!(c.is_null(2));
    }

    #[test]
    fn test_cast_timestamp_to_string() {
        let a = TimestampMillisecondArray::from_opt_vec(
            vec![Some(864000000005), Some(1545696000001), None],
            Some("UTC".to_string()),
        );
        let array = Arc::new(a) as ArrayRef;
        dbg!(&array);
        let b = cast(&array, &DataType::Utf8).unwrap();
        let c = b.as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(&DataType::Utf8, c.data_type());
        assert_eq!("1997-05-19 00:00:00.005", c.value(0));
        assert_eq!("2018-12-25 00:00:00.001", c.value(1));
        assert!(c.is_null(2));
    }

    #[test]
    fn test_cast_between_timestamps() {
        let a = TimestampMillisecondArray::from_opt_vec(
            vec![Some(864000003005), Some(1545696002001), None],
            None,
        );
        let array = Arc::new(a) as ArrayRef;
        let b = cast(&array, &DataType::Timestamp(TimeUnit::Second, None)).unwrap();
        let c = b.as_any().downcast_ref::<TimestampSecondArray>().unwrap();
        assert_eq!(864000003, c.value(0));
        assert_eq!(1545696002, c.value(1));
        assert!(c.is_null(2));
    }

    #[test]
    fn test_cast_to_strings() {
        let a = Arc::new(Int32Array::from(vec![1, 2, 3])) as ArrayRef;
        let out = cast(&a, &DataType::Utf8).unwrap();
        let out = out
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(out, vec![Some("1"), Some("2"), Some("3")]);
        let out = cast(&a, &DataType::LargeUtf8).unwrap();
        let out = out
            .as_any()
            .downcast_ref::<LargeStringArray>()
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(out, vec![Some("1"), Some("2"), Some("3")]);
    }

    #[test]
    fn test_str_to_str_casts() {
        for data in vec![
            vec![Some("foo"), Some("bar"), Some("ham")],
            vec![Some("foo"), None, Some("bar")],
        ] {
            let a = Arc::new(LargeStringArray::from(data.clone())) as ArrayRef;
            let to = cast(&a, &DataType::Utf8).unwrap();
            let expect = a
                .as_any()
                .downcast_ref::<LargeStringArray>()
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>();
            let out = to
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>();
            assert_eq!(expect, out);

            let a = Arc::new(StringArray::from(data)) as ArrayRef;
            let to = cast(&a, &DataType::LargeUtf8).unwrap();
            let expect = a
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>();
            let out = to
                .as_any()
                .downcast_ref::<LargeStringArray>()
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>();
            assert_eq!(expect, out);
        }
    }

    #[test]
    fn test_cast_from_f64() {
        let f64_values: Vec<f64> = vec![
            std::i64::MIN as f64,
            std::i32::MIN as f64,
            std::i16::MIN as f64,
            std::i8::MIN as f64,
            0_f64,
            std::u8::MAX as f64,
            std::u16::MAX as f64,
            std::u32::MAX as f64,
            std::u64::MAX as f64,
        ];
        let f64_array: ArrayRef = Arc::new(Float64Array::from(f64_values));

        let f64_expected = vec![
            "-9223372036854776000.0",
            "-2147483648.0",
            "-32768.0",
            "-128.0",
            "0.0",
            "255.0",
            "65535.0",
            "4294967295.0",
            "18446744073709552000.0",
        ];
        assert_eq!(
            f64_expected,
            get_cast_values::<Float64Type>(&f64_array, &DataType::Float64)
        );

        let f32_expected = vec![
            "-9223372000000000000.0",
            "-2147483600.0",
            "-32768.0",
            "-128.0",
            "0.0",
            "255.0",
            "65535.0",
            "4294967300.0",
            "18446744000000000000.0",
        ];
        assert_eq!(
            f32_expected,
            get_cast_values::<Float32Type>(&f64_array, &DataType::Float32)
        );

        let i64_expected = vec![
            "-9223372036854775808",
            "-2147483648",
            "-32768",
            "-128",
            "0",
            "255",
            "65535",
            "4294967295",
            "null",
        ];
        assert_eq!(
            i64_expected,
            get_cast_values::<Int64Type>(&f64_array, &DataType::Int64)
        );

        let i32_expected = vec![
            "null",
            "-2147483648",
            "-32768",
            "-128",
            "0",
            "255",
            "65535",
            "null",
            "null",
        ];
        assert_eq!(
            i32_expected,
            get_cast_values::<Int32Type>(&f64_array, &DataType::Int32)
        );

        let i16_expected = vec![
            "null", "null", "-32768", "-128", "0", "255", "null", "null", "null",
        ];
        assert_eq!(
            i16_expected,
            get_cast_values::<Int16Type>(&f64_array, &DataType::Int16)
        );

        let i8_expected = vec![
            "null", "null", "null", "-128", "0", "null", "null", "null", "null",
        ];
        assert_eq!(
            i8_expected,
            get_cast_values::<Int8Type>(&f64_array, &DataType::Int8)
        );

        let u64_expected = vec![
            "null",
            "null",
            "null",
            "null",
            "0",
            "255",
            "65535",
            "4294967295",
            "null",
        ];
        assert_eq!(
            u64_expected,
            get_cast_values::<UInt64Type>(&f64_array, &DataType::UInt64)
        );

        let u32_expected = vec![
            "null",
            "null",
            "null",
            "null",
            "0",
            "255",
            "65535",
            "4294967295",
            "null",
        ];
        assert_eq!(
            u32_expected,
            get_cast_values::<UInt32Type>(&f64_array, &DataType::UInt32)
        );

        let u16_expected = vec![
            "null", "null", "null", "null", "0", "255", "65535", "null", "null",
        ];
        assert_eq!(
            u16_expected,
            get_cast_values::<UInt16Type>(&f64_array, &DataType::UInt16)
        );

        let u8_expected = vec![
            "null", "null", "null", "null", "0", "255", "null", "null", "null",
        ];
        assert_eq!(
            u8_expected,
            get_cast_values::<UInt8Type>(&f64_array, &DataType::UInt8)
        );
    }

    #[test]
    fn test_cast_from_f32() {
        let f32_values: Vec<f32> = vec![
            std::i32::MIN as f32,
            std::i32::MIN as f32,
            std::i16::MIN as f32,
            std::i8::MIN as f32,
            0_f32,
            std::u8::MAX as f32,
            std::u16::MAX as f32,
            std::u32::MAX as f32,
            std::u32::MAX as f32,
        ];
        let f32_array: ArrayRef = Arc::new(Float32Array::from(f32_values));

        let f64_expected = vec![
            "-2147483648.0",
            "-2147483648.0",
            "-32768.0",
            "-128.0",
            "0.0",
            "255.0",
            "65535.0",
            "4294967296.0",
            "4294967296.0",
        ];
        assert_eq!(
            f64_expected,
            get_cast_values::<Float64Type>(&f32_array, &DataType::Float64)
        );

        let f32_expected = vec![
            "-2147483600.0",
            "-2147483600.0",
            "-32768.0",
            "-128.0",
            "0.0",
            "255.0",
            "65535.0",
            "4294967300.0",
            "4294967300.0",
        ];
        assert_eq!(
            f32_expected,
            get_cast_values::<Float32Type>(&f32_array, &DataType::Float32)
        );

        let i64_expected = vec![
            "-2147483648",
            "-2147483648",
            "-32768",
            "-128",
            "0",
            "255",
            "65535",
            "4294967296",
            "4294967296",
        ];
        assert_eq!(
            i64_expected,
            get_cast_values::<Int64Type>(&f32_array, &DataType::Int64)
        );

        let i32_expected = vec![
            "-2147483648",
            "-2147483648",
            "-32768",
            "-128",
            "0",
            "255",
            "65535",
            "null",
            "null",
        ];
        assert_eq!(
            i32_expected,
            get_cast_values::<Int32Type>(&f32_array, &DataType::Int32)
        );

        let i16_expected = vec![
            "null", "null", "-32768", "-128", "0", "255", "null", "null", "null",
        ];
        assert_eq!(
            i16_expected,
            get_cast_values::<Int16Type>(&f32_array, &DataType::Int16)
        );

        let i8_expected = vec![
            "null", "null", "null", "-128", "0", "null", "null", "null", "null",
        ];
        assert_eq!(
            i8_expected,
            get_cast_values::<Int8Type>(&f32_array, &DataType::Int8)
        );

        let u64_expected = vec![
            "null",
            "null",
            "null",
            "null",
            "0",
            "255",
            "65535",
            "4294967296",
            "4294967296",
        ];
        assert_eq!(
            u64_expected,
            get_cast_values::<UInt64Type>(&f32_array, &DataType::UInt64)
        );

        let u32_expected = vec![
            "null", "null", "null", "null", "0", "255", "65535", "null", "null",
        ];
        assert_eq!(
            u32_expected,
            get_cast_values::<UInt32Type>(&f32_array, &DataType::UInt32)
        );

        let u16_expected = vec![
            "null", "null", "null", "null", "0", "255", "65535", "null", "null",
        ];
        assert_eq!(
            u16_expected,
            get_cast_values::<UInt16Type>(&f32_array, &DataType::UInt16)
        );

        let u8_expected = vec![
            "null", "null", "null", "null", "0", "255", "null", "null", "null",
        ];
        assert_eq!(
            u8_expected,
            get_cast_values::<UInt8Type>(&f32_array, &DataType::UInt8)
        );
    }

    #[test]
    fn test_cast_from_uint64() {
        let u64_values: Vec<u64> = vec![
            0,
            std::u8::MAX as u64,
            std::u16::MAX as u64,
            std::u32::MAX as u64,
            std::u64::MAX,
        ];
        let u64_array: ArrayRef = Arc::new(UInt64Array::from(u64_values));

        let f64_expected = vec![
            "0.0",
            "255.0",
            "65535.0",
            "4294967295.0",
            "18446744073709552000.0",
        ];
        assert_eq!(
            f64_expected,
            get_cast_values::<Float64Type>(&u64_array, &DataType::Float64)
        );

        let f32_expected = vec![
            "0.0",
            "255.0",
            "65535.0",
            "4294967300.0",
            "18446744000000000000.0",
        ];
        assert_eq!(
            f32_expected,
            get_cast_values::<Float32Type>(&u64_array, &DataType::Float32)
        );

        let i64_expected = vec!["0", "255", "65535", "4294967295", "null"];
        assert_eq!(
            i64_expected,
            get_cast_values::<Int64Type>(&u64_array, &DataType::Int64)
        );

        let i32_expected = vec!["0", "255", "65535", "null", "null"];
        assert_eq!(
            i32_expected,
            get_cast_values::<Int32Type>(&u64_array, &DataType::Int32)
        );

        let i16_expected = vec!["0", "255", "null", "null", "null"];
        assert_eq!(
            i16_expected,
            get_cast_values::<Int16Type>(&u64_array, &DataType::Int16)
        );

        let i8_expected = vec!["0", "null", "null", "null", "null"];
        assert_eq!(
            i8_expected,
            get_cast_values::<Int8Type>(&u64_array, &DataType::Int8)
        );

        let u64_expected =
            vec!["0", "255", "65535", "4294967295", "18446744073709551615"];
        assert_eq!(
            u64_expected,
            get_cast_values::<UInt64Type>(&u64_array, &DataType::UInt64)
        );

        let u32_expected = vec!["0", "255", "65535", "4294967295", "null"];
        assert_eq!(
            u32_expected,
            get_cast_values::<UInt32Type>(&u64_array, &DataType::UInt32)
        );

        let u16_expected = vec!["0", "255", "65535", "null", "null"];
        assert_eq!(
            u16_expected,
            get_cast_values::<UInt16Type>(&u64_array, &DataType::UInt16)
        );

        let u8_expected = vec!["0", "255", "null", "null", "null"];
        assert_eq!(
            u8_expected,
            get_cast_values::<UInt8Type>(&u64_array, &DataType::UInt8)
        );
    }

    #[test]
    fn test_cast_from_uint32() {
        let u32_values: Vec<u32> = vec![
            0,
            std::u8::MAX as u32,
            std::u16::MAX as u32,
            std::u32::MAX as u32,
        ];
        let u32_array: ArrayRef = Arc::new(UInt32Array::from(u32_values));

        let f64_expected = vec!["0.0", "255.0", "65535.0", "4294967295.0"];
        assert_eq!(
            f64_expected,
            get_cast_values::<Float64Type>(&u32_array, &DataType::Float64)
        );

        let f32_expected = vec!["0.0", "255.0", "65535.0", "4294967300.0"];
        assert_eq!(
            f32_expected,
            get_cast_values::<Float32Type>(&u32_array, &DataType::Float32)
        );

        let i64_expected = vec!["0", "255", "65535", "4294967295"];
        assert_eq!(
            i64_expected,
            get_cast_values::<Int64Type>(&u32_array, &DataType::Int64)
        );

        let i32_expected = vec!["0", "255", "65535", "null"];
        assert_eq!(
            i32_expected,
            get_cast_values::<Int32Type>(&u32_array, &DataType::Int32)
        );

        let i16_expected = vec!["0", "255", "null", "null"];
        assert_eq!(
            i16_expected,
            get_cast_values::<Int16Type>(&u32_array, &DataType::Int16)
        );

        let i8_expected = vec!["0", "null", "null", "null"];
        assert_eq!(
            i8_expected,
            get_cast_values::<Int8Type>(&u32_array, &DataType::Int8)
        );

        let u64_expected = vec!["0", "255", "65535", "4294967295"];
        assert_eq!(
            u64_expected,
            get_cast_values::<UInt64Type>(&u32_array, &DataType::UInt64)
        );

        let u32_expected = vec!["0", "255", "65535", "4294967295"];
        assert_eq!(
            u32_expected,
            get_cast_values::<UInt32Type>(&u32_array, &DataType::UInt32)
        );

        let u16_expected = vec!["0", "255", "65535", "null"];
        assert_eq!(
            u16_expected,
            get_cast_values::<UInt16Type>(&u32_array, &DataType::UInt16)
        );

        let u8_expected = vec!["0", "255", "null", "null"];
        assert_eq!(
            u8_expected,
            get_cast_values::<UInt8Type>(&u32_array, &DataType::UInt8)
        );
    }

    #[test]
    fn test_cast_from_uint16() {
        let u16_values: Vec<u16> = vec![0, std::u8::MAX as u16, std::u16::MAX as u16];
        let u16_array: ArrayRef = Arc::new(UInt16Array::from(u16_values));

        let f64_expected = vec!["0.0", "255.0", "65535.0"];
        assert_eq!(
            f64_expected,
            get_cast_values::<Float64Type>(&u16_array, &DataType::Float64)
        );

        let f32_expected = vec!["0.0", "255.0", "65535.0"];
        assert_eq!(
            f32_expected,
            get_cast_values::<Float32Type>(&u16_array, &DataType::Float32)
        );

        let i64_expected = vec!["0", "255", "65535"];
        assert_eq!(
            i64_expected,
            get_cast_values::<Int64Type>(&u16_array, &DataType::Int64)
        );

        let i32_expected = vec!["0", "255", "65535"];
        assert_eq!(
            i32_expected,
            get_cast_values::<Int32Type>(&u16_array, &DataType::Int32)
        );

        let i16_expected = vec!["0", "255", "null"];
        assert_eq!(
            i16_expected,
            get_cast_values::<Int16Type>(&u16_array, &DataType::Int16)
        );

        let i8_expected = vec!["0", "null", "null"];
        assert_eq!(
            i8_expected,
            get_cast_values::<Int8Type>(&u16_array, &DataType::Int8)
        );

        let u64_expected = vec!["0", "255", "65535"];
        assert_eq!(
            u64_expected,
            get_cast_values::<UInt64Type>(&u16_array, &DataType::UInt64)
        );

        let u32_expected = vec!["0", "255", "65535"];
        assert_eq!(
            u32_expected,
            get_cast_values::<UInt32Type>(&u16_array, &DataType::UInt32)
        );

        let u16_expected = vec!["0", "255", "65535"];
        assert_eq!(
            u16_expected,
            get_cast_values::<UInt16Type>(&u16_array, &DataType::UInt16)
        );

        let u8_expected = vec!["0", "255", "null"];
        assert_eq!(
            u8_expected,
            get_cast_values::<UInt8Type>(&u16_array, &DataType::UInt8)
        );
    }

    #[test]
    fn test_cast_from_uint8() {
        let u8_values: Vec<u8> = vec![0, std::u8::MAX];
        let u8_array: ArrayRef = Arc::new(UInt8Array::from(u8_values));

        let f64_expected = vec!["0.0", "255.0"];
        assert_eq!(
            f64_expected,
            get_cast_values::<Float64Type>(&u8_array, &DataType::Float64)
        );

        let f32_expected = vec!["0.0", "255.0"];
        assert_eq!(
            f32_expected,
            get_cast_values::<Float32Type>(&u8_array, &DataType::Float32)
        );

        let i64_expected = vec!["0", "255"];
        assert_eq!(
            i64_expected,
            get_cast_values::<Int64Type>(&u8_array, &DataType::Int64)
        );

        let i32_expected = vec!["0", "255"];
        assert_eq!(
            i32_expected,
            get_cast_values::<Int32Type>(&u8_array, &DataType::Int32)
        );

        let i16_expected = vec!["0", "255"];
        assert_eq!(
            i16_expected,
            get_cast_values::<Int16Type>(&u8_array, &DataType::Int16)
        );

        let i8_expected = vec!["0", "null"];
        assert_eq!(
            i8_expected,
            get_cast_values::<Int8Type>(&u8_array, &DataType::Int8)
        );

        let u64_expected = vec!["0", "255"];
        assert_eq!(
            u64_expected,
            get_cast_values::<UInt64Type>(&u8_array, &DataType::UInt64)
        );

        let u32_expected = vec!["0", "255"];
        assert_eq!(
            u32_expected,
            get_cast_values::<UInt32Type>(&u8_array, &DataType::UInt32)
        );

        let u16_expected = vec!["0", "255"];
        assert_eq!(
            u16_expected,
            get_cast_values::<UInt16Type>(&u8_array, &DataType::UInt16)
        );

        let u8_expected = vec!["0", "255"];
        assert_eq!(
            u8_expected,
            get_cast_values::<UInt8Type>(&u8_array, &DataType::UInt8)
        );
    }

    #[test]
    fn test_cast_from_int64() {
        let i64_values: Vec<i64> = vec![
            std::i64::MIN,
            std::i32::MIN as i64,
            std::i16::MIN as i64,
            std::i8::MIN as i64,
            0,
            std::i8::MAX as i64,
            std::i16::MAX as i64,
            std::i32::MAX as i64,
            std::i64::MAX,
        ];
        let i64_array: ArrayRef = Arc::new(Int64Array::from(i64_values));

        let f64_expected = vec![
            "-9223372036854776000.0",
            "-2147483648.0",
            "-32768.0",
            "-128.0",
            "0.0",
            "127.0",
            "32767.0",
            "2147483647.0",
            "9223372036854776000.0",
        ];
        assert_eq!(
            f64_expected,
            get_cast_values::<Float64Type>(&i64_array, &DataType::Float64)
        );

        let f32_expected = vec![
            "-9223372000000000000.0",
            "-2147483600.0",
            "-32768.0",
            "-128.0",
            "0.0",
            "127.0",
            "32767.0",
            "2147483600.0",
            "9223372000000000000.0",
        ];
        assert_eq!(
            f32_expected,
            get_cast_values::<Float32Type>(&i64_array, &DataType::Float32)
        );

        let i64_expected = vec![
            "-9223372036854775808",
            "-2147483648",
            "-32768",
            "-128",
            "0",
            "127",
            "32767",
            "2147483647",
            "9223372036854775807",
        ];
        assert_eq!(
            i64_expected,
            get_cast_values::<Int64Type>(&i64_array, &DataType::Int64)
        );

        let i32_expected = vec![
            "null",
            "-2147483648",
            "-32768",
            "-128",
            "0",
            "127",
            "32767",
            "2147483647",
            "null",
        ];
        assert_eq!(
            i32_expected,
            get_cast_values::<Int32Type>(&i64_array, &DataType::Int32)
        );

        assert_eq!(
            i32_expected,
            get_cast_values::<Date32Type>(&i64_array, &DataType::Date32)
        );

        let i16_expected = vec![
            "null", "null", "-32768", "-128", "0", "127", "32767", "null", "null",
        ];
        assert_eq!(
            i16_expected,
            get_cast_values::<Int16Type>(&i64_array, &DataType::Int16)
        );

        let i8_expected = vec![
            "null", "null", "null", "-128", "0", "127", "null", "null", "null",
        ];
        assert_eq!(
            i8_expected,
            get_cast_values::<Int8Type>(&i64_array, &DataType::Int8)
        );

        let u64_expected = vec![
            "null",
            "null",
            "null",
            "null",
            "0",
            "127",
            "32767",
            "2147483647",
            "9223372036854775807",
        ];
        assert_eq!(
            u64_expected,
            get_cast_values::<UInt64Type>(&i64_array, &DataType::UInt64)
        );

        let u32_expected = vec![
            "null",
            "null",
            "null",
            "null",
            "0",
            "127",
            "32767",
            "2147483647",
            "null",
        ];
        assert_eq!(
            u32_expected,
            get_cast_values::<UInt32Type>(&i64_array, &DataType::UInt32)
        );

        let u16_expected = vec![
            "null", "null", "null", "null", "0", "127", "32767", "null", "null",
        ];
        assert_eq!(
            u16_expected,
            get_cast_values::<UInt16Type>(&i64_array, &DataType::UInt16)
        );

        let u8_expected = vec![
            "null", "null", "null", "null", "0", "127", "null", "null", "null",
        ];
        assert_eq!(
            u8_expected,
            get_cast_values::<UInt8Type>(&i64_array, &DataType::UInt8)
        );
    }

    #[test]
    fn test_cast_from_int32() {
        let i32_values: Vec<i32> = vec![
            std::i32::MIN as i32,
            std::i16::MIN as i32,
            std::i8::MIN as i32,
            0,
            std::i8::MAX as i32,
            std::i16::MAX as i32,
            std::i32::MAX as i32,
        ];
        let i32_array: ArrayRef = Arc::new(Int32Array::from(i32_values));

        let f64_expected = vec![
            "-2147483648.0",
            "-32768.0",
            "-128.0",
            "0.0",
            "127.0",
            "32767.0",
            "2147483647.0",
        ];
        assert_eq!(
            f64_expected,
            get_cast_values::<Float64Type>(&i32_array, &DataType::Float64)
        );

        let f32_expected = vec![
            "-2147483600.0",
            "-32768.0",
            "-128.0",
            "0.0",
            "127.0",
            "32767.0",
            "2147483600.0",
        ];
        assert_eq!(
            f32_expected,
            get_cast_values::<Float32Type>(&i32_array, &DataType::Float32)
        );

        let i16_expected = vec!["null", "-32768", "-128", "0", "127", "32767", "null"];
        assert_eq!(
            i16_expected,
            get_cast_values::<Int16Type>(&i32_array, &DataType::Int16)
        );

        let i8_expected = vec!["null", "null", "-128", "0", "127", "null", "null"];
        assert_eq!(
            i8_expected,
            get_cast_values::<Int8Type>(&i32_array, &DataType::Int8)
        );

        let u64_expected =
            vec!["null", "null", "null", "0", "127", "32767", "2147483647"];
        assert_eq!(
            u64_expected,
            get_cast_values::<UInt64Type>(&i32_array, &DataType::UInt64)
        );

        let u32_expected =
            vec!["null", "null", "null", "0", "127", "32767", "2147483647"];
        assert_eq!(
            u32_expected,
            get_cast_values::<UInt32Type>(&i32_array, &DataType::UInt32)
        );

        let u16_expected = vec!["null", "null", "null", "0", "127", "32767", "null"];
        assert_eq!(
            u16_expected,
            get_cast_values::<UInt16Type>(&i32_array, &DataType::UInt16)
        );

        let u8_expected = vec!["null", "null", "null", "0", "127", "null", "null"];
        assert_eq!(
            u8_expected,
            get_cast_values::<UInt8Type>(&i32_array, &DataType::UInt8)
        );

        // The date32 to date64 cast increases the numerical values in order to keep the same dates.
        let i64_expected = vec![
            "-185542587187200000",
            "-2831155200000",
            "-11059200000",
            "0",
            "10972800000",
            "2831068800000",
            "185542587100800000",
        ];
        assert_eq!(
            i64_expected,
            get_cast_values::<Date64Type>(&i32_array, &DataType::Date64)
        );
    }

    #[test]
    fn test_cast_from_int16() {
        let i16_values: Vec<i16> = vec![
            std::i16::MIN,
            std::i8::MIN as i16,
            0,
            std::i8::MAX as i16,
            std::i16::MAX,
        ];
        let i16_array: ArrayRef = Arc::new(Int16Array::from(i16_values));

        let f64_expected = vec!["-32768.0", "-128.0", "0.0", "127.0", "32767.0"];
        assert_eq!(
            f64_expected,
            get_cast_values::<Float64Type>(&i16_array, &DataType::Float64)
        );

        let f32_expected = vec!["-32768.0", "-128.0", "0.0", "127.0", "32767.0"];
        assert_eq!(
            f32_expected,
            get_cast_values::<Float32Type>(&i16_array, &DataType::Float32)
        );

        let i64_expected = vec!["-32768", "-128", "0", "127", "32767"];
        assert_eq!(
            i64_expected,
            get_cast_values::<Int64Type>(&i16_array, &DataType::Int64)
        );

        let i32_expected = vec!["-32768", "-128", "0", "127", "32767"];
        assert_eq!(
            i32_expected,
            get_cast_values::<Int32Type>(&i16_array, &DataType::Int32)
        );

        let i16_expected = vec!["-32768", "-128", "0", "127", "32767"];
        assert_eq!(
            i16_expected,
            get_cast_values::<Int16Type>(&i16_array, &DataType::Int16)
        );

        let i8_expected = vec!["null", "-128", "0", "127", "null"];
        assert_eq!(
            i8_expected,
            get_cast_values::<Int8Type>(&i16_array, &DataType::Int8)
        );

        let u64_expected = vec!["null", "null", "0", "127", "32767"];
        assert_eq!(
            u64_expected,
            get_cast_values::<UInt64Type>(&i16_array, &DataType::UInt64)
        );

        let u32_expected = vec!["null", "null", "0", "127", "32767"];
        assert_eq!(
            u32_expected,
            get_cast_values::<UInt32Type>(&i16_array, &DataType::UInt32)
        );

        let u16_expected = vec!["null", "null", "0", "127", "32767"];
        assert_eq!(
            u16_expected,
            get_cast_values::<UInt16Type>(&i16_array, &DataType::UInt16)
        );

        let u8_expected = vec!["null", "null", "0", "127", "null"];
        assert_eq!(
            u8_expected,
            get_cast_values::<UInt8Type>(&i16_array, &DataType::UInt8)
        );
    }

    #[test]
    fn test_cast_from_date32() {
        let i32_values: Vec<i32> = vec![
            std::i32::MIN as i32,
            std::i16::MIN as i32,
            std::i8::MIN as i32,
            0,
            std::i8::MAX as i32,
            std::i16::MAX as i32,
            std::i32::MAX as i32,
        ];
        let date32_array: ArrayRef = Arc::new(Date32Array::from(i32_values));

        let i64_expected = vec![
            "-2147483648",
            "-32768",
            "-128",
            "0",
            "127",
            "32767",
            "2147483647",
        ];
        assert_eq!(
            i64_expected,
            get_cast_values::<Int64Type>(&date32_array, &DataType::Int64)
        );
    }

    #[test]
    fn test_cast_from_int8() {
        let i8_values: Vec<i8> = vec![std::i8::MIN, 0, std::i8::MAX];
        let i8_array: ArrayRef = Arc::new(Int8Array::from(i8_values));

        let f64_expected = vec!["-128.0", "0.0", "127.0"];
        assert_eq!(
            f64_expected,
            get_cast_values::<Float64Type>(&i8_array, &DataType::Float64)
        );

        let f32_expected = vec!["-128.0", "0.0", "127.0"];
        assert_eq!(
            f32_expected,
            get_cast_values::<Float32Type>(&i8_array, &DataType::Float32)
        );

        let i64_expected = vec!["-128", "0", "127"];
        assert_eq!(
            i64_expected,
            get_cast_values::<Int64Type>(&i8_array, &DataType::Int64)
        );

        let i32_expected = vec!["-128", "0", "127"];
        assert_eq!(
            i32_expected,
            get_cast_values::<Int32Type>(&i8_array, &DataType::Int32)
        );

        let i16_expected = vec!["-128", "0", "127"];
        assert_eq!(
            i16_expected,
            get_cast_values::<Int16Type>(&i8_array, &DataType::Int16)
        );

        let i8_expected = vec!["-128", "0", "127"];
        assert_eq!(
            i8_expected,
            get_cast_values::<Int8Type>(&i8_array, &DataType::Int8)
        );

        let u64_expected = vec!["null", "0", "127"];
        assert_eq!(
            u64_expected,
            get_cast_values::<UInt64Type>(&i8_array, &DataType::UInt64)
        );

        let u32_expected = vec!["null", "0", "127"];
        assert_eq!(
            u32_expected,
            get_cast_values::<UInt32Type>(&i8_array, &DataType::UInt32)
        );

        let u16_expected = vec!["null", "0", "127"];
        assert_eq!(
            u16_expected,
            get_cast_values::<UInt16Type>(&i8_array, &DataType::UInt16)
        );

        let u8_expected = vec!["null", "0", "127"];
        assert_eq!(
            u8_expected,
            get_cast_values::<UInt8Type>(&i8_array, &DataType::UInt8)
        );
    }

    /// Convert `array` into a vector of strings by casting to data type dt
    fn get_cast_values<T>(array: &ArrayRef, dt: &DataType) -> Vec<String>
    where
        T: ArrowNumericType,
    {
        let c = cast(&array, dt).unwrap();
        let a = c.as_any().downcast_ref::<PrimitiveArray<T>>().unwrap();
        let mut v: Vec<String> = vec![];
        for i in 0..array.len() {
            if a.is_null(i) {
                v.push("null".to_string())
            } else {
                v.push(format!("{:?}", a.value(i)));
            }
        }
        v
    }

    #[test]
    fn test_cast_utf8_dict() {
        // FROM a dictionary with of Utf8 values
        use DataType::*;

        let keys_builder = PrimitiveBuilder::<Int8Type>::new(10);
        let values_builder = StringBuilder::new(10);
        let mut builder = StringDictionaryBuilder::new(keys_builder, values_builder);
        builder.append("one").unwrap();
        builder.append_null().unwrap();
        builder.append("three").unwrap();
        let array: ArrayRef = Arc::new(builder.finish());

        let expected = vec!["one", "null", "three"];

        // Test casting TO StringArray
        let cast_type = Utf8;
        let cast_array = cast(&array, &cast_type).expect("cast to UTF-8 failed");
        assert_eq!(cast_array.data_type(), &cast_type);
        assert_eq!(array_to_strings(&cast_array), expected);

        // Test casting TO Dictionary (with different index sizes)

        let cast_type = Dictionary(Box::new(Int16), Box::new(Utf8));
        let cast_array = cast(&array, &cast_type).expect("cast failed");
        assert_eq!(cast_array.data_type(), &cast_type);
        assert_eq!(array_to_strings(&cast_array), expected);

        let cast_type = Dictionary(Box::new(Int32), Box::new(Utf8));
        let cast_array = cast(&array, &cast_type).expect("cast failed");
        assert_eq!(cast_array.data_type(), &cast_type);
        assert_eq!(array_to_strings(&cast_array), expected);

        let cast_type = Dictionary(Box::new(Int64), Box::new(Utf8));
        let cast_array = cast(&array, &cast_type).expect("cast failed");
        assert_eq!(cast_array.data_type(), &cast_type);
        assert_eq!(array_to_strings(&cast_array), expected);

        let cast_type = Dictionary(Box::new(UInt8), Box::new(Utf8));
        let cast_array = cast(&array, &cast_type).expect("cast failed");
        assert_eq!(cast_array.data_type(), &cast_type);
        assert_eq!(array_to_strings(&cast_array), expected);

        let cast_type = Dictionary(Box::new(UInt16), Box::new(Utf8));
        let cast_array = cast(&array, &cast_type).expect("cast failed");
        assert_eq!(cast_array.data_type(), &cast_type);
        assert_eq!(array_to_strings(&cast_array), expected);

        let cast_type = Dictionary(Box::new(UInt32), Box::new(Utf8));
        let cast_array = cast(&array, &cast_type).expect("cast failed");
        assert_eq!(cast_array.data_type(), &cast_type);
        assert_eq!(array_to_strings(&cast_array), expected);

        let cast_type = Dictionary(Box::new(UInt64), Box::new(Utf8));
        let cast_array = cast(&array, &cast_type).expect("cast failed");
        assert_eq!(cast_array.data_type(), &cast_type);
        assert_eq!(array_to_strings(&cast_array), expected);
    }

    #[test]
    fn test_cast_dict_to_dict_bad_index_value_primitive() {
        use DataType::*;
        // test converting from an array that has indexes of a type
        // that are out of bounds for a particular other kind of
        // index.

        let keys_builder = PrimitiveBuilder::<Int32Type>::new(10);
        let values_builder = PrimitiveBuilder::<Int64Type>::new(10);
        let mut builder = PrimitiveDictionaryBuilder::new(keys_builder, values_builder);

        // add 200 distinct values (which can be stored by a
        // dictionary indexed by int32, but not a dictionary indexed
        // with int8)
        for i in 0..200 {
            builder.append(i).unwrap();
        }
        let array: ArrayRef = Arc::new(builder.finish());

        let cast_type = Dictionary(Box::new(Int8), Box::new(Utf8));
        let res = cast(&array, &cast_type);
        assert!(res.is_err());
        let actual_error = format!("{:?}", res);
        let expected_error = "Could not convert 72 dictionary indexes from Int32 to Int8";
        assert!(
            actual_error.contains(expected_error),
            "did not find expected error '{}' in actual error '{}'",
            actual_error,
            expected_error
        );
    }

    #[test]
    fn test_cast_dict_to_dict_bad_index_value_utf8() {
        use DataType::*;
        // Same test as test_cast_dict_to_dict_bad_index_value but use
        // string values (and encode the expected behavior here);

        let keys_builder = PrimitiveBuilder::<Int32Type>::new(10);
        let values_builder = StringBuilder::new(10);
        let mut builder = StringDictionaryBuilder::new(keys_builder, values_builder);

        // add 200 distinct values (which can be stored by a
        // dictionary indexed by int32, but not a dictionary indexed
        // with int8)
        for i in 0..200 {
            let val = format!("val{}", i);
            builder.append(&val).unwrap();
        }
        let array: ArrayRef = Arc::new(builder.finish());

        let cast_type = Dictionary(Box::new(Int8), Box::new(Utf8));
        let res = cast(&array, &cast_type);
        assert!(res.is_err());
        let actual_error = format!("{:?}", res);
        let expected_error = "Could not convert 72 dictionary indexes from Int32 to Int8";
        assert!(
            actual_error.contains(expected_error),
            "did not find expected error '{}' in actual error '{}'",
            actual_error,
            expected_error
        );
    }

    #[test]
    fn test_cast_primitive_dict() {
        // FROM a dictionary with of INT32 values
        use DataType::*;

        let keys_builder = PrimitiveBuilder::<Int8Type>::new(10);
        let values_builder = PrimitiveBuilder::<Int32Type>::new(10);
        let mut builder = PrimitiveDictionaryBuilder::new(keys_builder, values_builder);
        builder.append(1).unwrap();
        builder.append_null().unwrap();
        builder.append(3).unwrap();
        let array: ArrayRef = Arc::new(builder.finish());

        let expected = vec!["1", "null", "3"];

        // Test casting TO PrimitiveArray, different dictionary type
        let cast_array = cast(&array, &Utf8).expect("cast to UTF-8 failed");
        assert_eq!(array_to_strings(&cast_array), expected);
        assert_eq!(cast_array.data_type(), &Utf8);

        let cast_array = cast(&array, &Int64).expect("cast to int64 failed");
        assert_eq!(array_to_strings(&cast_array), expected);
        assert_eq!(cast_array.data_type(), &Int64);
    }

    #[test]
    fn test_cast_primitive_array_to_dict() {
        use DataType::*;

        let mut builder = PrimitiveBuilder::<Int32Type>::new(10);
        builder.append_value(1).unwrap();
        builder.append_null().unwrap();
        builder.append_value(3).unwrap();
        let array: ArrayRef = Arc::new(builder.finish());

        let expected = vec!["1", "null", "3"];

        // Cast to a dictionary (same value type, Int32)
        let cast_type = Dictionary(Box::new(UInt8), Box::new(Int32));
        let cast_array = cast(&array, &cast_type).expect("cast failed");
        assert_eq!(cast_array.data_type(), &cast_type);
        assert_eq!(array_to_strings(&cast_array), expected);

        // Cast to a dictionary (different value type, Int8)
        let cast_type = Dictionary(Box::new(UInt8), Box::new(Int8));
        let cast_array = cast(&array, &cast_type).expect("cast failed");
        assert_eq!(cast_array.data_type(), &cast_type);
        assert_eq!(array_to_strings(&cast_array), expected);
    }

    #[test]
    fn test_cast_string_array_to_dict() {
        use DataType::*;

        let array = Arc::new(StringArray::from(vec![Some("one"), None, Some("three")]))
            as ArrayRef;

        let expected = vec!["one", "null", "three"];

        // Cast to a dictionary (same value type, Utf8)
        let cast_type = Dictionary(Box::new(UInt8), Box::new(Utf8));
        let cast_array = cast(&array, &cast_type).expect("cast failed");
        assert_eq!(cast_array.data_type(), &cast_type);
        assert_eq!(array_to_strings(&cast_array), expected);
    }

    #[test]
    fn test_cast_null_array_to_int32() {
        let array = Arc::new(NullArray::new(6)) as ArrayRef;

        let expected = Int32Array::from(vec![None; 6]);

        // Cast to a dictionary (same value type, Utf8)
        let cast_type = DataType::Int32;
        let cast_array = cast(&array, &cast_type).expect("cast failed");
        let cast_array = as_primitive_array::<Int32Type>(&cast_array);
        assert_eq!(cast_array.data_type(), &cast_type);
        assert_eq!(cast_array, &expected);
    }

    /// Print the `DictionaryArray` `array` as a vector of strings
    fn array_to_strings(array: &ArrayRef) -> Vec<String> {
        (0..array.len())
            .map(|i| {
                if array.is_null(i) {
                    "null".to_string()
                } else {
                    array_value_to_string(array, i).expect("Convert array to String")
                }
            })
            .collect()
    }

    #[test]
    fn test_cast_utf8_to_date32() {
        use chrono::NaiveDate;
        let from_ymd = chrono::NaiveDate::from_ymd;
        let since = chrono::NaiveDate::signed_duration_since;

        let a = StringArray::from(vec![
            "2000-01-01",          // valid date with leading 0s
            "2000-2-2",            // valid date without leading 0s
            "2000-00-00",          // invalid month and day
            "2000-01-01T12:00:00", // date + time is invalid
            "2000",                // just a year is invalid
        ]);
        let array = Arc::new(a) as ArrayRef;
        let b = cast(&array, &DataType::Date32).unwrap();
        let c = b.as_any().downcast_ref::<Date32Array>().unwrap();

        // test valid inputs
        let date_value = since(NaiveDate::from_ymd(2000, 1, 1), from_ymd(1970, 1, 1))
            .num_days() as i32;
        assert!(c.is_valid(0)); // "2000-01-01"
        assert_eq!(date_value, c.value(0));

        let date_value = since(NaiveDate::from_ymd(2000, 2, 2), from_ymd(1970, 1, 1))
            .num_days() as i32;
        assert!(c.is_valid(1)); // "2000-2-2"
        assert_eq!(date_value, c.value(1));

        // test invalid inputs
        assert!(!c.is_valid(2)); // "2000-00-00"
        assert!(!c.is_valid(3)); // "2000-01-01T12:00:00"
        assert!(!c.is_valid(4)); // "2000"
    }

    #[test]
    fn test_cast_utf8_to_date64() {
        let a = StringArray::from(vec![
            "2000-01-01T12:00:00", // date + time valid
            "2020-12-15T12:34:56", // date + time valid
            "2020-2-2T12:34:56",   // valid date time without leading 0s
            "2000-00-00T12:00:00", // invalid month and day
            "2000-01-01 12:00:00", // missing the 'T'
            "2000-01-01",          // just a date is invalid
        ]);
        let array = Arc::new(a) as ArrayRef;
        let b = cast(&array, &DataType::Date64).unwrap();
        let c = b.as_any().downcast_ref::<Date64Array>().unwrap();

        // test valid inputs
        assert!(c.is_valid(0)); // "2000-01-01T12:00:00"
        assert_eq!(946728000000, c.value(0));
        assert!(c.is_valid(1)); // "2020-12-15T12:34:56"
        assert_eq!(1608035696000, c.value(1));
        assert!(c.is_valid(2)); // "2020-2-2T12:34:56"
        assert_eq!(1580646896000, c.value(2));

        // test invalid inputs
        assert!(!c.is_valid(3)); // "2000-00-00T12:00:00"
        assert!(!c.is_valid(4)); // "2000-01-01 12:00:00"
        assert!(!c.is_valid(5)); // "2000-01-01"
    }

    #[test]
    #[cfg_attr(miri, ignore)] // running forever
    fn test_can_cast_types() {
        // this function attempts to ensure that can_cast_types stays
        // in sync with cast.  It simply tries all combinations of
        // types and makes sure that if `can_cast_types` returns
        // true, so does `cast`

        let all_types = get_all_types();

        for array in get_arrays_of_all_types() {
            for to_type in &all_types {
                println!("Test casting {:?} --> {:?}", array.data_type(), to_type);
                let cast_result = cast(&array, &to_type);
                let reported_cast_ability = can_cast_types(array.data_type(), to_type);

                // check for mismatch
                match (cast_result, reported_cast_ability) {
                    (Ok(_), false) => {
                        panic!("Was able to cast array {:?} from {:?} to {:?} but can_cast_types reported false",
                               array, array.data_type(), to_type)
                    }
                    (Err(e), true) => {
                        panic!("Was not able to cast array {:?} from {:?} to {:?} but can_cast_types reported true. \
                                Error was {:?}",
                               array, array.data_type(), to_type, e)
                    }
                    // otherwise it was a match
                    _ => {}
                };
            }
        }
    }

    #[test]
    fn test_cast_list_containers() {
        // large-list to list
        let array = Arc::new(make_large_list_array()) as ArrayRef;
        let list_array = cast(
            &array,
            &DataType::List(Box::new(Field::new("", DataType::Int32, false))),
        )
        .unwrap();
        let actual = list_array.as_any().downcast_ref::<ListArray>().unwrap();
        let expected = array.as_any().downcast_ref::<LargeListArray>().unwrap();

        assert_eq!(&expected.value(0), &actual.value(0));
        assert_eq!(&expected.value(1), &actual.value(1));
        assert_eq!(&expected.value(2), &actual.value(2));

        // list to large-list
        let array = Arc::new(make_list_array()) as ArrayRef;
        let large_list_array = cast(
            &array,
            &DataType::LargeList(Box::new(Field::new("", DataType::Int32, false))),
        )
        .unwrap();
        let actual = large_list_array
            .as_any()
            .downcast_ref::<LargeListArray>()
            .unwrap();
        let expected = array.as_any().downcast_ref::<ListArray>().unwrap();

        assert_eq!(&expected.value(0), &actual.value(0));
        assert_eq!(&expected.value(1), &actual.value(1));
        assert_eq!(&expected.value(2), &actual.value(2));
    }

    /// Create instances of arrays with varying types for cast tests
    fn get_arrays_of_all_types() -> Vec<ArrayRef> {
        let tz_name = String::from("America/New_York");
        let binary_data: Vec<&[u8]> = vec![b"foo", b"bar"];
        vec![
            Arc::new(BinaryArray::from(binary_data.clone())),
            Arc::new(LargeBinaryArray::from(binary_data.clone())),
            make_dictionary_primitive::<Int8Type>(),
            make_dictionary_primitive::<Int16Type>(),
            make_dictionary_primitive::<Int32Type>(),
            make_dictionary_primitive::<Int64Type>(),
            make_dictionary_primitive::<UInt8Type>(),
            make_dictionary_primitive::<UInt16Type>(),
            make_dictionary_primitive::<UInt32Type>(),
            make_dictionary_primitive::<UInt64Type>(),
            make_dictionary_utf8::<Int8Type>(),
            make_dictionary_utf8::<Int16Type>(),
            make_dictionary_utf8::<Int32Type>(),
            make_dictionary_utf8::<Int64Type>(),
            make_dictionary_utf8::<UInt8Type>(),
            make_dictionary_utf8::<UInt16Type>(),
            make_dictionary_utf8::<UInt32Type>(),
            make_dictionary_utf8::<UInt64Type>(),
            Arc::new(make_list_array()),
            Arc::new(make_large_list_array()),
            Arc::new(make_fixed_size_list_array()),
            Arc::new(make_fixed_size_binary_array()),
            Arc::new(StructArray::from(vec![
                (
                    Field::new("a", DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![false, false, true, true]))
                        as Arc<Array>,
                ),
                (
                    Field::new("b", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![42, 28, 19, 31])),
                ),
            ])),
            //Arc::new(make_union_array()),
            Arc::new(NullArray::new(10)),
            Arc::new(StringArray::from(vec!["foo", "bar"])),
            Arc::new(LargeStringArray::from(vec!["foo", "bar"])),
            Arc::new(BooleanArray::from(vec![true, false])),
            Arc::new(Int8Array::from(vec![1, 2])),
            Arc::new(Int16Array::from(vec![1, 2])),
            Arc::new(Int32Array::from(vec![1, 2])),
            Arc::new(Int64Array::from(vec![1, 2])),
            Arc::new(UInt8Array::from(vec![1, 2])),
            Arc::new(UInt16Array::from(vec![1, 2])),
            Arc::new(UInt32Array::from(vec![1, 2])),
            Arc::new(UInt64Array::from(vec![1, 2])),
            Arc::new(Float32Array::from(vec![1.0, 2.0])),
            Arc::new(Float64Array::from(vec![1.0, 2.0])),
            Arc::new(TimestampSecondArray::from_vec(vec![1000, 2000], None)),
            Arc::new(TimestampMillisecondArray::from_vec(vec![1000, 2000], None)),
            Arc::new(TimestampMicrosecondArray::from_vec(vec![1000, 2000], None)),
            Arc::new(TimestampNanosecondArray::from_vec(vec![1000, 2000], None)),
            Arc::new(TimestampSecondArray::from_vec(
                vec![1000, 2000],
                Some(tz_name.clone()),
            )),
            Arc::new(TimestampMillisecondArray::from_vec(
                vec![1000, 2000],
                Some(tz_name.clone()),
            )),
            Arc::new(TimestampMicrosecondArray::from_vec(
                vec![1000, 2000],
                Some(tz_name.clone()),
            )),
            Arc::new(TimestampNanosecondArray::from_vec(
                vec![1000, 2000],
                Some(tz_name),
            )),
            Arc::new(Date32Array::from(vec![1000, 2000])),
            Arc::new(Date64Array::from(vec![1000, 2000])),
            Arc::new(Time32SecondArray::from(vec![1000, 2000])),
            Arc::new(Time32MillisecondArray::from(vec![1000, 2000])),
            Arc::new(Time64MicrosecondArray::from(vec![1000, 2000])),
            Arc::new(Time64NanosecondArray::from(vec![1000, 2000])),
            Arc::new(IntervalYearMonthArray::from(vec![1000, 2000])),
            Arc::new(IntervalDayTimeArray::from(vec![1000, 2000])),
            Arc::new(DurationSecondArray::from(vec![1000, 2000])),
            Arc::new(DurationMillisecondArray::from(vec![1000, 2000])),
            Arc::new(DurationMicrosecondArray::from(vec![1000, 2000])),
            Arc::new(DurationNanosecondArray::from(vec![1000, 2000])),
        ]
    }

    fn make_list_array() -> ListArray {
        // Construct a value array
        let value_data = ArrayData::builder(DataType::Int32)
            .len(8)
            .add_buffer(Buffer::from_slice_ref(&[0, 1, 2, 3, 4, 5, 6, 7]))
            .build();

        // Construct a buffer for value offsets, for the nested array:
        //  [[0, 1, 2], [3, 4, 5], [6, 7]]
        let value_offsets = Buffer::from_slice_ref(&[0, 3, 6, 8]);

        // Construct a list array from the above two
        let list_data_type =
            DataType::List(Box::new(Field::new("item", DataType::Int32, true)));
        let list_data = ArrayData::builder(list_data_type)
            .len(3)
            .add_buffer(value_offsets)
            .add_child_data(value_data)
            .build();
        ListArray::from(list_data)
    }

    fn make_large_list_array() -> LargeListArray {
        // Construct a value array
        let value_data = ArrayData::builder(DataType::Int32)
            .len(8)
            .add_buffer(Buffer::from_slice_ref(&[0, 1, 2, 3, 4, 5, 6, 7]))
            .build();

        // Construct a buffer for value offsets, for the nested array:
        //  [[0, 1, 2], [3, 4, 5], [6, 7]]
        let value_offsets = Buffer::from_slice_ref(&[0i64, 3, 6, 8]);

        // Construct a list array from the above two
        let list_data_type =
            DataType::LargeList(Box::new(Field::new("item", DataType::Int32, true)));
        let list_data = ArrayData::builder(list_data_type)
            .len(3)
            .add_buffer(value_offsets)
            .add_child_data(value_data)
            .build();
        LargeListArray::from(list_data)
    }

    fn make_fixed_size_list_array() -> FixedSizeListArray {
        // Construct a value array
        let value_data = ArrayData::builder(DataType::Int32)
            .len(10)
            .add_buffer(Buffer::from_slice_ref(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]))
            .build();

        // Construct a fixed size list array from the above two
        let list_data_type = DataType::FixedSizeList(
            Box::new(Field::new("item", DataType::Int32, true)),
            2,
        );
        let list_data = ArrayData::builder(list_data_type)
            .len(5)
            .add_child_data(value_data)
            .build();
        FixedSizeListArray::from(list_data)
    }

    fn make_fixed_size_binary_array() -> FixedSizeBinaryArray {
        let values: [u8; 15] = *b"hellotherearrow";

        let array_data = ArrayData::builder(DataType::FixedSizeBinary(5))
            .len(3)
            .add_buffer(Buffer::from(&values[..]))
            .build();
        FixedSizeBinaryArray::from(array_data)
    }

    fn make_union_array() -> UnionArray {
        let mut builder = UnionBuilder::new_dense(7);
        builder.append::<Int32Type>("a", 1).unwrap();
        builder.append::<Int64Type>("b", 2).unwrap();
        builder.build().unwrap()
    }

    /// Creates a dictionary with primitive dictionary values, and keys of type K
    fn make_dictionary_primitive<K: ArrowDictionaryKeyType>() -> ArrayRef {
        let keys_builder = PrimitiveBuilder::<K>::new(2);
        // Pick Int32 arbitrarily for dictionary values
        let values_builder = PrimitiveBuilder::<Int32Type>::new(2);
        let mut b = PrimitiveDictionaryBuilder::new(keys_builder, values_builder);
        b.append(1).unwrap();
        b.append(2).unwrap();
        Arc::new(b.finish())
    }

    /// Creates a dictionary with utf8 values, and keys of type K
    fn make_dictionary_utf8<K: ArrowDictionaryKeyType>() -> ArrayRef {
        let keys_builder = PrimitiveBuilder::<K>::new(2);
        // Pick Int32 arbitrarily for dictionary values
        let values_builder = StringBuilder::new(2);
        let mut b = StringDictionaryBuilder::new(keys_builder, values_builder);
        b.append("foo").unwrap();
        b.append("bar").unwrap();
        Arc::new(b.finish())
    }

    // Get a selection of datatypes to try and cast to
    fn get_all_types() -> Vec<DataType> {
        use DataType::*;
        let tz_name = String::from("America/New_York");

        vec![
            Null,
            Boolean,
            Int8,
            Int16,
            Int32,
            UInt64,
            UInt8,
            UInt16,
            UInt32,
            UInt64,
            Float16,
            Float32,
            Float64,
            Timestamp(TimeUnit::Second, None),
            Timestamp(TimeUnit::Millisecond, None),
            Timestamp(TimeUnit::Microsecond, None),
            Timestamp(TimeUnit::Nanosecond, None),
            Timestamp(TimeUnit::Second, Some(tz_name.clone())),
            Timestamp(TimeUnit::Millisecond, Some(tz_name.clone())),
            Timestamp(TimeUnit::Microsecond, Some(tz_name.clone())),
            Timestamp(TimeUnit::Nanosecond, Some(tz_name)),
            Date32,
            Date64,
            Time32(TimeUnit::Second),
            Time32(TimeUnit::Millisecond),
            Time64(TimeUnit::Microsecond),
            Time64(TimeUnit::Nanosecond),
            Duration(TimeUnit::Second),
            Duration(TimeUnit::Millisecond),
            Duration(TimeUnit::Microsecond),
            Duration(TimeUnit::Nanosecond),
            Interval(IntervalUnit::YearMonth),
            Interval(IntervalUnit::DayTime),
            Binary,
            FixedSizeBinary(10),
            LargeBinary,
            Utf8,
            LargeUtf8,
            List(Box::new(Field::new("item", DataType::Int8, true))),
            List(Box::new(Field::new("item", DataType::Utf8, true))),
            FixedSizeList(Box::new(Field::new("item", DataType::Int8, true)), 10),
            FixedSizeList(Box::new(Field::new("item", DataType::Utf8, false)), 10),
            LargeList(Box::new(Field::new("item", DataType::Int8, true))),
            LargeList(Box::new(Field::new("item", DataType::Utf8, false))),
            Struct(vec![
                Field::new("f1", DataType::Int32, false),
                Field::new("f2", DataType::Utf8, true),
            ]),
            Union(vec![
                Field::new("f1", DataType::Int32, false),
                Field::new("f2", DataType::Utf8, true),
            ]),
            Dictionary(Box::new(DataType::Int8), Box::new(DataType::Int32)),
            Dictionary(Box::new(DataType::Int16), Box::new(DataType::Utf8)),
            Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
        ]
    }

    #[test]
    fn test_utf8_cast_offsets() {
        // test if offset of the array is taken into account during cast
        let str_array = StringArray::from(vec!["a", "b", "c"]);
        let str_array = str_array.slice(1, 2);

        let out = cast(&str_array, &DataType::LargeUtf8).unwrap();

        let large_str_array = out.as_any().downcast_ref::<LargeStringArray>().unwrap();
        let strs = large_str_array.into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(strs, &["b", "c"])
    }

    #[test]
    fn test_list_cast_offsets() {
        // test if offset of the array is taken into account during cast
        let array1 = make_list_array().slice(1, 2);
        let array2 = Arc::new(make_list_array()) as ArrayRef;

        let dt = DataType::LargeList(Box::new(Field::new("item", DataType::Int32, true)));
        let out1 = cast(&array1, &dt).unwrap();
        let out2 = cast(&array2, &dt).unwrap();

        assert_eq!(&out1, &out2.slice(1, 2))
    }
}
