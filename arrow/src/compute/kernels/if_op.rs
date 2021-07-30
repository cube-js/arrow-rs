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

//! If flow control kernel

use crate::array::{
    Array, ArrayData, BooleanArray, PrimitiveArray, StringArray, StringBuilder,
};
use crate::buffer::Buffer;
use crate::datatypes;
use crate::datatypes::ToByteSlice;
use crate::error::{ArrowError, Result};

pub fn if_primitive<T>(
    condition: &BooleanArray,
    then_values: &PrimitiveArray<T>,
    else_values: &PrimitiveArray<T>,
) -> Result<PrimitiveArray<T>>
where
    T: datatypes::ArrowNumericType,
{
    if condition.len() != then_values.len() || condition.len() != else_values.len() {
        return Err(ArrowError::ComputeError(
            "Cannot perform if operation on arrays of different length".to_string(),
        ));
    }

    let mut null_bit_builder = BooleanArray::builder(condition.len());

    for i in 0..condition.len() {
        if condition.is_valid(i) && condition.value(i) {
            if then_values.is_valid(i) {
                null_bit_builder.append_value(true)?;
            } else {
                null_bit_builder.append_null()?;
            }
        } else if else_values.is_valid(i) {
            null_bit_builder.append_value(true)?;
        } else {
            null_bit_builder.append_null()?;
        }
    }

    let null_bit_array = null_bit_builder.finish();

    let values = (0..condition.len())
        .map(|i| {
            if condition.is_valid(i) && condition.value(i) {
                then_values.value(i)
            } else {
                else_values.value(i)
            }
        })
        .collect::<Vec<T::Native>>();

    let data = ArrayData::new(
        T::DATA_TYPE,
        condition.len(),
        None,
        null_bit_array.data_ref().null_buffer().cloned(),
        0,
        vec![Buffer::from(values.to_byte_slice())],
        vec![],
    );
    Ok(PrimitiveArray::<T>::from(data))
}

pub fn if_string(
    condition: &BooleanArray,
    then_values: &StringArray,
    else_values: &StringArray,
) -> Result<StringArray> {
    if condition.len() != then_values.len() || condition.len() != else_values.len() {
        return Err(ArrowError::ComputeError(
            "Cannot perform if operation on arrays of different length".to_string(),
        ));
    }

    let mut builder = StringBuilder::new(condition.len());

    for i in 0..condition.len() {
        if condition.is_valid(i) && condition.value(i) {
            if then_values.is_valid(i) {
                builder.append_value(then_values.value(i))?;
            } else {
                builder.append_null()?;
            }
        } else if else_values.is_valid(i) {
            builder.append_value(else_values.value(i))?;
        } else {
            builder.append_null()?;
        }
    }

    Ok(builder.finish())
}
