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

//! Defines merge sort and join kernels

use std::sync::Arc;

use crate::array::*;
use crate::datatypes::*;
use crate::error::{ArrowError, Result};

use crate::compute::{total_cmp_32, total_cmp_64};
use core::fmt;
use std::cmp::Ordering;
use std::fmt::{Debug, Display, Formatter};

type JoinCursorAndIndices = (usize, bool, Arc<UInt32Array>);
type CursorAndIndices = (usize, Arc<UInt32Array>);

#[derive(Debug)]
pub enum MergeJoinType {
    Inner,
    Left,
    Right,
}

/// Merge join two arrays
pub fn merge_join_indices<'a>(
    left: &'a [ArrayRef],
    right: &'a [ArrayRef],
    left_cursor: usize,
    right_cursor: usize,
    last_left: bool,
    last_right: bool,
    join_type: MergeJoinType,
) -> Result<(JoinCursorAndIndices, JoinCursorAndIndices)> {
    let arrays: Vec<&'a [ArrayRef]> = vec![left, right];

    let comparators = comparators_for(arrays)?;

    let mut left_indices = Vec::<Option<u32>>::new();
    let mut right_indices = Vec::<Option<u32>>::new();

    let left_size = left[0].len();
    let right_size = right[0].len();

    let mut left_merge_cursor = MergeRowCursor::new(&comparators, 0, left_cursor);
    let mut right_merge_cursor = MergeRowCursor::new(&comparators, 1, right_cursor);

    let mut advance_left = false;
    let mut advance_right = false;

    while left_merge_cursor.within_range() && right_merge_cursor.within_range() {
        left_merge_cursor.check_consistency()?;
        right_merge_cursor.check_consistency()?;
        let ordering = left_merge_cursor.cmp(&right_merge_cursor);
        match ordering {
            Ordering::Equal => {
                let mut left_equal_end = left_merge_cursor.next();
                let mut right_equal_end = right_merge_cursor.next();
                while left_equal_end.row_index < left_size
                    && left_equal_end == right_merge_cursor
                {
                    left_equal_end = left_equal_end.next();
                }
                while right_equal_end.row_index < right_size
                    && left_merge_cursor == right_equal_end
                {
                    right_equal_end = right_equal_end.next();
                }
                if left_merge_cursor.is_valid()
                    && right_merge_cursor.is_valid()
                    && (left_equal_end.row_index == left_size && !last_left
                        || right_equal_end.row_index == right_size && !last_right)
                {
                    advance_left = left_equal_end.row_index == left_size && !last_left;
                    advance_right =
                        right_equal_end.row_index == right_size && !last_right;
                    break;
                }
                if left_merge_cursor.is_valid() && right_merge_cursor.is_valid() {
                    for li in left_merge_cursor.row_index..left_equal_end.row_index {
                        for ri in right_merge_cursor.row_index..right_equal_end.row_index
                        {
                            left_indices.push(Some(li as u32));
                            right_indices.push(Some(ri as u32));
                        }
                    }
                } else if let MergeJoinType::Left = join_type {
                    for li in left_merge_cursor.row_index..left_equal_end.row_index {
                        left_indices.push(Some(li as u32));
                        right_indices.push(None);
                    }
                } else if let MergeJoinType::Right = join_type {
                    for ri in right_merge_cursor.row_index..right_equal_end.row_index {
                        left_indices.push(None);
                        right_indices.push(Some(ri as u32));
                    }
                }
                left_merge_cursor = left_equal_end;
                right_merge_cursor = right_equal_end;
            }
            Ordering::Less => {
                if let MergeJoinType::Left = join_type {
                    left_indices.push(Some(left_merge_cursor.row_index as u32));
                    right_indices.push(None);
                }
                left_merge_cursor = left_merge_cursor.next();
            }
            Ordering::Greater => {
                if let MergeJoinType::Right = join_type {
                    left_indices.push(None);
                    right_indices.push(Some(right_merge_cursor.row_index as u32));
                }
                right_merge_cursor = right_merge_cursor.next();
            }
        }
    }

    if last_right && !advance_left && !advance_right {
        while left_merge_cursor.within_range() {
            if let MergeJoinType::Left = join_type {
                left_indices.push(Some(left_merge_cursor.row_index as u32));
                right_indices.push(None);
            }
            left_merge_cursor = left_merge_cursor.next();
        }
    }

    if last_left && !advance_left && !advance_right {
        while right_merge_cursor.within_range() {
            if let MergeJoinType::Right = join_type {
                left_indices.push(None);
                right_indices.push(Some(right_merge_cursor.row_index as u32));
            }
            right_merge_cursor = right_merge_cursor.next();
        }
    }

    let left_indices_array = UInt32Array::from(left_indices);
    let right_indices_array = UInt32Array::from(right_indices);

    Ok((
        (
            left_merge_cursor.row_index,
            advance_left,
            Arc::new(left_indices_array),
        ),
        (
            right_merge_cursor.row_index,
            advance_right,
            Arc::new(right_indices_array),
        ),
    ))
}

fn comparators_for<'a>(
    arrays: Vec<&'a [ArrayRef]>,
) -> Result<Vec<Box<dyn ArrayComparator + 'a>>> {
    let mut comparators: Vec<Box<dyn ArrayComparator + 'a>> = Vec::new();
    for column_index in 0..arrays[0].len() {
        let to_compare = arrays.iter().map(|a| &a[column_index]).collect::<Vec<_>>();
        if !to_compare
            .iter()
            .all(|a| a.data_type() == to_compare[0].data_type())
        {
            return Err(ArrowError::SchemaError(format!(
                "Mismatched data types for merge join: {:?}",
                to_compare.iter().map(|c| c.data_type()).collect::<Vec<_>>()
            )));
        }

        let comparator: Box<dyn ArrayComparator + 'a> = match to_compare[0].data_type() {
            DataType::Int8 => Box::new(PrimitiveComparator::<Int8Type>::new(to_compare)),
            DataType::Int16 => {
                Box::new(PrimitiveComparator::<Int16Type>::new(to_compare))
            }
            DataType::Int32 => {
                Box::new(PrimitiveComparator::<Int32Type>::new(to_compare))
            }
            DataType::Int64 => {
                Box::new(PrimitiveComparator::<Int64Type>::new(to_compare))
            }
            DataType::Int96 => {
                Box::new(PrimitiveComparator::<Int96Type>::new(to_compare))
            }
            DataType::Int64Decimal(0) => {
                Box::new(PrimitiveComparator::<Int64Decimal0Type>::new(to_compare))
            }
            DataType::Int64Decimal(1) => {
                Box::new(PrimitiveComparator::<Int64Decimal1Type>::new(to_compare))
            }
            DataType::Int64Decimal(2) => {
                Box::new(PrimitiveComparator::<Int64Decimal2Type>::new(to_compare))
            }
            DataType::Int64Decimal(3) => {
                Box::new(PrimitiveComparator::<Int64Decimal3Type>::new(to_compare))
            }
            DataType::Int64Decimal(4) => {
                Box::new(PrimitiveComparator::<Int64Decimal4Type>::new(to_compare))
            }
            DataType::Int64Decimal(5) => {
                Box::new(PrimitiveComparator::<Int64Decimal5Type>::new(to_compare))
            }
            DataType::Int64Decimal(10) => {
                Box::new(PrimitiveComparator::<Int64Decimal10Type>::new(to_compare))
            }
            DataType::Int96Decimal(0) => {
                Box::new(PrimitiveComparator::<Int96Decimal0Type>::new(to_compare))
            }
            DataType::Int96Decimal(1) => {
                Box::new(PrimitiveComparator::<Int96Decimal1Type>::new(to_compare))
            }
            DataType::Int96Decimal(2) => {
                Box::new(PrimitiveComparator::<Int96Decimal2Type>::new(to_compare))
            }
            DataType::Int96Decimal(3) => {
                Box::new(PrimitiveComparator::<Int96Decimal3Type>::new(to_compare))
            }
            DataType::Int96Decimal(4) => {
                Box::new(PrimitiveComparator::<Int96Decimal4Type>::new(to_compare))
            }
            DataType::Int96Decimal(5) => {
                Box::new(PrimitiveComparator::<Int96Decimal5Type>::new(to_compare))
            }
            DataType::Int96Decimal(10) => {
                Box::new(PrimitiveComparator::<Int96Decimal10Type>::new(to_compare))
            }
            DataType::UInt8 => {
                Box::new(PrimitiveComparator::<UInt8Type>::new(to_compare))
            }
            DataType::UInt16 => {
                Box::new(PrimitiveComparator::<UInt16Type>::new(to_compare))
            }
            DataType::UInt32 => {
                Box::new(PrimitiveComparator::<UInt32Type>::new(to_compare))
            }
            DataType::UInt64 => {
                Box::new(PrimitiveComparator::<UInt64Type>::new(to_compare))
            }
            DataType::Float64 => {
                Box::new(FloatComparator::<Float64Type>::new(&to_compare))
            }
            DataType::Float32 => {
                Box::new(FloatComparator::<Float32Type>::new(&to_compare))
            }
            DataType::Time32(TimeUnit::Second) => {
                Box::new(PrimitiveComparator::<Time32SecondType>::new(to_compare))
            }
            DataType::Time32(TimeUnit::Millisecond) => {
                Box::new(PrimitiveComparator::<Time32MillisecondType>::new(
                    to_compare,
                ))
            }
            DataType::Time64(TimeUnit::Microsecond) => {
                Box::new(PrimitiveComparator::<Time64MicrosecondType>::new(
                    to_compare,
                ))
            }
            DataType::Time64(TimeUnit::Nanosecond) => {
                Box::new(PrimitiveComparator::<Time64NanosecondType>::new(to_compare))
            }
            DataType::Timestamp(TimeUnit::Second, _) => {
                Box::new(PrimitiveComparator::<TimestampSecondType>::new(to_compare))
            }
            DataType::Timestamp(TimeUnit::Millisecond, _) => Box::new(
                PrimitiveComparator::<TimestampMillisecondType>::new(to_compare),
            ),
            DataType::Timestamp(TimeUnit::Microsecond, _) => Box::new(
                PrimitiveComparator::<TimestampMicrosecondType>::new(to_compare),
            ),
            DataType::Timestamp(TimeUnit::Nanosecond, _) => Box::new(
                PrimitiveComparator::<TimestampNanosecondType>::new(to_compare),
            ),
            DataType::Boolean => Box::new(BooleanComparator::new(to_compare)),
            DataType::Utf8 => Box::new(StringComparator::new(to_compare)),
            t => {
                unimplemented!("Merge operations are not supported for data type {:?}", t)
            }
        };
        comparators.push(comparator);
    }
    Ok(comparators)
}

pub struct MergeRowCursor<'a> {
    comparators: &'a [Box<dyn ArrayComparator + 'a>],
    array_index: usize,
    row_index: usize,
}

impl<'a> MergeRowCursor<'a> {
    fn new(
        comparators: &'a [Box<dyn ArrayComparator + 'a>],
        array_index: usize,
        row_index: usize,
    ) -> Self {
        Self {
            comparators,
            array_index,
            row_index,
        }
    }

    fn next(&self) -> Self {
        Self {
            comparators: self.comparators,
            row_index: self.row_index + 1,
            array_index: self.array_index,
        }
    }

    fn advance(&self, row_index: usize) -> Self {
        Self {
            comparators: self.comparators,
            row_index,
            array_index: self.array_index,
        }
    }

    fn check_consistency(&self) -> Result<()> {
        if self.row_index > 0 {
            let prev_point =
                Self::new(self.comparators, self.array_index, self.row_index - 1);
            if &prev_point > self {
                return Err(ArrowError::InvalidArgumentError(format!(
                    "Merge operation on unsorted data: {:?}, {:?}",
                    prev_point, self
                )));
            }
        }
        Ok(())
    }

    fn compare(&self, other: &Self) -> Ordering {
        self.comparators.iter().fold(Ordering::Equal, |a, b| {
            a.then(b.compare(
                self.array_index,
                self.row_index,
                other.array_index,
                other.row_index,
            ))
        })
    }

    fn within_range(&self) -> bool {
        self.comparators
            .iter()
            .all(|c| c.within_range(self.array_index, self.row_index))
    }

    fn is_valid(&self) -> bool {
        self.comparators
            .iter()
            .all(|c| c.is_valid(self.array_index, self.row_index))
    }
}

impl<'a> PartialOrd for MergeRowCursor<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(std::cmp::Ord::cmp(self, other))
    }
}

impl<'a> PartialEq for MergeRowCursor<'a> {
    fn eq(&self, other: &MergeRowCursor) -> bool {
        self.compare(other) == Ordering::Equal
    }
}

impl<'a> Eq for MergeRowCursor<'a> {}
impl<'a> Ord for MergeRowCursor<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compare(other)
    }
}

impl<'a> Debug for MergeRowCursor<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Cursor [array: {}, row: {}, value: {:?}]",
            self.array_index,
            self.row_index,
            self.comparators
                .iter()
                .map(|c| c.debug_value(self.array_index, self.row_index))
                .collect::<Vec<_>>()
        )
    }
}

pub trait ArrayComparator {
    fn compare(
        &self,
        left_array_index: usize,
        left_row_index: usize,
        right_array_index: usize,
        right_row_index: usize,
    ) -> Ordering;

    fn within_range(&self, array_index: usize, row_index: usize) -> bool;

    fn debug_value(&self, array_index: usize, row_index: usize) -> Box<dyn Debug>;

    fn is_valid(&self, array_index: usize, row_index: usize) -> bool;
}

#[derive(Debug)]
pub struct StringComparator<'a> {
    arrays: Vec<&'a StringArray>,
}

impl<'a> StringComparator<'a> {
    fn new(arrays: Vec<&'a ArrayRef>) -> Self {
        Self {
            arrays: arrays
                .into_iter()
                .map(|array| array.as_any().downcast_ref::<StringArray>().unwrap())
                .collect(),
        }
    }
}

impl<'a> ArrayComparator for StringComparator<'a> {
    fn compare(
        &self,
        left_array_index: usize,
        left_row_index: usize,
        right_array_index: usize,
        right_row_index: usize,
    ) -> Ordering {
        let left = self.arrays[left_array_index];
        let right = self.arrays[right_array_index];
        let left_null = left.is_null(left_row_index);
        let right_null = right.is_null(right_row_index);
        if left_null && right_null {
            Ordering::Equal
        } else if right_null {
            Ordering::Greater
        } else if left_null {
            Ordering::Less
        } else {
            let left_value = left.value(left_row_index);
            let right_value = right.value(right_row_index);
            left_value.cmp(right_value)
        }
    }

    fn within_range(&self, array_index: usize, row_index: usize) -> bool {
        row_index < self.arrays[array_index].len()
    }

    fn debug_value(&self, array_index: usize, row_index: usize) -> Box<dyn Debug> {
        Box::new(self.arrays[array_index].value(row_index).to_string())
    }

    fn is_valid(&self, array_index: usize, row_index: usize) -> bool {
        self.arrays[array_index].is_valid(row_index)
    }
}

#[derive(Debug)]
pub struct BooleanComparator<'a> {
    arrays: Vec<&'a BooleanArray>,
}

impl<'a> BooleanComparator<'a> {
    fn new(arrays: Vec<&'a ArrayRef>) -> Self {
        Self {
            arrays: arrays
                .into_iter()
                .map(|array| array.as_any().downcast_ref::<BooleanArray>().unwrap())
                .collect(),
        }
    }
}

impl<'a> ArrayComparator for BooleanComparator<'a> {
    fn compare(
        &self,
        left_array_index: usize,
        left_row_index: usize,
        right_array_index: usize,
        right_row_index: usize,
    ) -> Ordering {
        let left = self.arrays[left_array_index];
        let right = self.arrays[right_array_index];
        let left_null = left.is_null(left_row_index);
        let right_null = right.is_null(right_row_index);
        if left_null && right_null {
            Ordering::Equal
        } else if right_null {
            Ordering::Greater
        } else if left_null {
            Ordering::Less
        } else {
            let left_value = left.value(left_row_index);
            let right_value = right.value(right_row_index);
            left_value.cmp(&right_value)
        }
    }

    fn within_range(&self, array_index: usize, row_index: usize) -> bool {
        row_index < self.arrays[array_index].len()
    }

    fn debug_value(&self, array_index: usize, row_index: usize) -> Box<dyn Debug> {
        Box::new(self.arrays[array_index].value(row_index))
    }

    fn is_valid(&self, array_index: usize, row_index: usize) -> bool {
        self.arrays[array_index].is_valid(row_index)
    }
}

#[derive(Debug)]
struct FloatComparator<'a, F: ArrowPrimitiveType> {
    arrays: Vec<&'a PrimitiveArray<F>>,
}

pub(crate) trait FloatCmp {
    fn total_cmp(self, r: Self) -> Ordering;
}

impl FloatCmp for f64 {
    fn total_cmp(self, r: Self) -> Ordering {
        total_cmp_64(self, r)
    }
}

impl FloatCmp for f32 {
    fn total_cmp(self, r: Self) -> Ordering {
        total_cmp_32(self, r)
    }
}
impl<'a, F> FloatComparator<'a, F>
where
    F: ArrowPrimitiveType,
    F::Native: FloatCmp,
{
    pub fn new(arrays: &[&'a ArrayRef]) -> Self {
        Self {
            arrays: arrays
                .iter()
                .map(|array| array.as_any().downcast_ref::<PrimitiveArray<F>>().unwrap())
                .collect(),
        }
    }
}

impl<'a, F> ArrayComparator for FloatComparator<'a, F>
where
    F: ArrowPrimitiveType,
    F::Native: FloatCmp,
{
    fn compare(
        &self,
        left_array_index: usize,
        left_row_index: usize,
        right_array_index: usize,
        right_row_index: usize,
    ) -> Ordering {
        let left = self.arrays[left_array_index];
        let right = self.arrays[right_array_index];
        let left_null = left.is_null(left_row_index);
        let right_null = right.is_null(right_row_index);
        if left_null && right_null {
            Ordering::Equal
        } else if right_null {
            Ordering::Greater
        } else if left_null {
            Ordering::Less
        } else {
            let left_value = left.value(left_row_index);
            let right_value = right.value(right_row_index);
            left_value.total_cmp(right_value)
        }
    }

    fn within_range(&self, array_index: usize, row_index: usize) -> bool {
        row_index < self.arrays[array_index].len()
    }

    fn debug_value(&self, array_index: usize, row_index: usize) -> Box<dyn Debug> {
        Box::new(self.arrays[array_index].value(row_index))
    }

    fn is_valid(&self, array_index: usize, row_index: usize) -> bool {
        self.arrays[array_index].is_valid(row_index)
    }
}

#[derive(Debug)]
pub struct PrimitiveComparator<'a, T: ArrowPrimitiveType>
where
    T::Native: Ord + Display,
{
    arrays: Vec<&'a PrimitiveArray<T>>,
}

impl<'a, T: ArrowPrimitiveType> PrimitiveComparator<'a, T>
where
    T::Native: Ord + Display,
{
    fn new(arrays: Vec<&'a ArrayRef>) -> Self {
        Self {
            arrays: arrays
                .into_iter()
                .map(|array| array.as_any().downcast_ref::<PrimitiveArray<T>>().unwrap())
                .collect(),
        }
    }
}

impl<'a, T: ArrowPrimitiveType> ArrayComparator for PrimitiveComparator<'a, T>
where
    T::Native: Ord + Display,
{
    fn compare(
        &self,
        left_array_index: usize,
        left_row_index: usize,
        right_array_index: usize,
        right_row_index: usize,
    ) -> Ordering {
        let left = self.arrays[left_array_index];
        let right = self.arrays[right_array_index];
        let left_null = left.is_null(left_row_index);
        let right_null = right.is_null(right_row_index);
        if left_null && right_null {
            Ordering::Equal
        } else if right_null {
            Ordering::Greater
        } else if left_null {
            Ordering::Less
        } else {
            let left_value = left.value(left_row_index);
            let right_value = right.value(right_row_index);
            left_value.cmp(&right_value)
        }
    }

    fn within_range(&self, array_index: usize, row_index: usize) -> bool {
        row_index < self.arrays[array_index].len()
    }

    fn debug_value(&self, array_index: usize, row_index: usize) -> Box<dyn Debug> {
        Box::new(self.arrays[array_index].value(row_index))
    }

    fn is_valid(&self, array_index: usize, row_index: usize) -> bool {
        self.arrays[array_index].is_valid(row_index)
    }
}

#[cfg(test)]
mod tests {
    use crate::array::{ArrayRef, UInt32Array, UInt64Array};
    use crate::compute::kernels::merge::{merge_join_indices, MergeJoinType};
    use std::sync::Arc;

    #[test]
    fn merge_join() {
        let array_left: ArrayRef = Arc::new(UInt64Array::from(vec![
            None,
            None,
            None,
            None,
            Some(4),
            Some(8),
            Some(9),
            Some(15),
        ]));
        let array_right: ArrayRef = Arc::new(UInt64Array::from(vec![
            None,
            Some(4),
            Some(7),
            Some(9),
            Some(15),
        ]));
        let vec_left = vec![array_left];
        let vec_right = vec![array_right];

        let result = merge_join_indices(
            vec_left.as_slice(),
            vec_right.as_slice(),
            0,
            0,
            true,
            true,
            MergeJoinType::Inner,
        )
        .unwrap();

        assert_eq!(
            result,
            (
                (8usize, false, Arc::new(UInt32Array::from(vec![4, 6, 7]))),
                (5usize, false, Arc::new(UInt32Array::from(vec![1, 3, 4])))
            )
        )
    }

    #[test]
    fn merge_left_join() {
        let array_left: ArrayRef = Arc::new(UInt64Array::from(vec![
            None,
            None,
            None,
            None,
            Some(4),
            Some(8),
            Some(9),
            Some(15),
            Some(15),
        ]));
        let array_right: ArrayRef = Arc::new(UInt64Array::from(vec![
            None,
            Some(4),
            Some(4),
            Some(7),
            Some(9),
            Some(15),
        ]));
        let vec_left = vec![array_left];
        let vec_right = vec![array_right];

        let result = merge_join_indices(
            vec_left.as_slice(),
            vec_right.as_slice(),
            0,
            0,
            true,
            true,
            MergeJoinType::Left,
        )
        .unwrap();

        assert_eq!(
            result,
            (
                (
                    9usize,
                    false,
                    Arc::new(UInt32Array::from(vec![
                        Some(0),
                        Some(1),
                        Some(2),
                        Some(3),
                        Some(4),
                        Some(4),
                        Some(5),
                        Some(6),
                        Some(7),
                        Some(8)
                    ]))
                ),
                (
                    6usize,
                    false,
                    Arc::new(UInt32Array::from(vec![
                        None,
                        None,
                        None,
                        None,
                        Some(1),
                        Some(2),
                        None,
                        Some(4),
                        Some(5),
                        Some(5)
                    ]))
                )
            )
        )
    }

    #[test]
    fn merge_left_join_last_right() {
        let array_left: ArrayRef =
            Arc::new(UInt64Array::from(vec![Some(2), Some(2), Some(2), Some(2)]));
        let array_right: ArrayRef = Arc::new(UInt64Array::from(vec![Some(1), Some(2)]));
        let vec_left = vec![array_left];
        let vec_right = vec![array_right];

        let result = merge_join_indices(
            vec_left.as_slice(),
            vec_right.as_slice(),
            0,
            1,
            false,
            true,
            MergeJoinType::Left,
        )
        .unwrap();

        assert_eq!(
            result,
            (
                (0usize, true, Arc::new(UInt32Array::from(Vec::<u32>::new()))),
                (
                    1usize,
                    false,
                    Arc::new(UInt32Array::from(Vec::<u32>::new()))
                )
            )
        )
    }

    #[test]
    fn merge_left_join_empty() {
        let array_left: ArrayRef = Arc::new(UInt64Array::from(vec![
            None,
            None,
            None,
            None,
            Some(4),
            Some(8),
            Some(9),
            Some(15),
            Some(15),
        ]));
        let array_right: ArrayRef = Arc::new(UInt64Array::from(Vec::<u64>::new()));
        let vec_left = vec![array_left];
        let vec_right = vec![array_right];

        let result = merge_join_indices(
            vec_left.as_slice(),
            vec_right.as_slice(),
            0,
            0,
            true,
            true,
            MergeJoinType::Left,
        )
        .unwrap();

        assert_eq!(
            result,
            (
                (
                    9usize,
                    false,
                    Arc::new(UInt32Array::from(vec![
                        Some(0),
                        Some(1),
                        Some(2),
                        Some(3),
                        Some(4),
                        Some(5),
                        Some(6),
                        Some(7),
                        Some(8)
                    ]))
                ),
                (
                    0,
                    false,
                    Arc::new(UInt32Array::from(vec![
                        None, None, None, None, None, None, None, None, None,
                    ]))
                )
            )
        )
    }
}
