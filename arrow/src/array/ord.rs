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

//! Contains functions and function factories to compare arrays.

use std::cmp::Ordering;

use crate::array::*;
use crate::datatypes::TimeUnit;
use crate::datatypes::*;
use crate::error::{ArrowError, Result};

use crate::compute::kernels::merge::FloatCmp;
use num::Float;

/// Compare the values at two arbitrary indices in two arrays.
pub type DynComparator = Box<dyn Fn(usize, usize) -> Ordering + Send + Sync>;

fn compare_primitives<T: ArrowPrimitiveType>(left: &Array, right: &Array) -> DynComparator
where
    T::Native: Ord,
{
    let left: PrimitiveArray<T> = PrimitiveArray::from(left.data().clone());
    let right: PrimitiveArray<T> = PrimitiveArray::from(right.data().clone());
    Box::new(move |i, j| left.value(i).cmp(&right.value(j)))
}

fn compare_boolean(left: &Array, right: &Array) -> DynComparator {
    let left: BooleanArray = BooleanArray::from(left.data().clone());
    let right: BooleanArray = BooleanArray::from(right.data().clone());

    Box::new(move |i, j| left.value(i).cmp(&right.value(j)))
}

fn compare_float<T: ArrowPrimitiveType>(left: &Array, right: &Array) -> DynComparator
where
    T::Native: Float + FloatCmp,
{
    let left: PrimitiveArray<T> = PrimitiveArray::from(left.data().clone());
    let right: PrimitiveArray<T> = PrimitiveArray::from(right.data().clone());
    // CubeStore-specific: use `total_cmp` instead of putting NaNs last.
    Box::new(move |i, j| left.value(i).total_cmp(right.value(j)))
}

fn compare_string<T>(left: &Array, right: &Array) -> DynComparator
where
    T: StringOffsetSizeTrait,
{
    let left: StringArray = StringArray::from(left.data().clone());
    let right: StringArray = StringArray::from(right.data().clone());

    Box::new(move |i, j| left.value(i).cmp(&right.value(j)))
}

fn compare_dict_string<T>(left: &Array, right: &Array) -> DynComparator
where
    T: ArrowDictionaryKeyType,
{
    let left = left.as_any().downcast_ref::<DictionaryArray<T>>().unwrap();
    let right = right.as_any().downcast_ref::<DictionaryArray<T>>().unwrap();

    let left_keys: PrimitiveArray<T> = PrimitiveArray::from(left.keys().data().clone());
    let right_keys: PrimitiveArray<T> = PrimitiveArray::from(right.keys().data().clone());
    let left_values = StringArray::from(left.values().data().clone());
    let right_values = StringArray::from(right.values().data().clone());

    Box::new(move |i: usize, j: usize| {
        let key_left = left_keys.value(i).to_usize().unwrap();
        let key_right = right_keys.value(j).to_usize().unwrap();
        let left = left_values.value(key_left);
        let right = right_values.value(key_right);
        left.cmp(&right)
    })
}

/// returns a comparison function that compares two values at two different positions
/// between the two arrays.
/// The arrays' types must be equal.
/// # Example
/// ```
/// use arrow::array::{build_compare, Int32Array};
///
/// # fn main() -> arrow::error::Result<()> {
/// let array1 = Int32Array::from(vec![1, 2]);
/// let array2 = Int32Array::from(vec![3, 4]);
///
/// let cmp = build_compare(&array1, &array2)?;
///
/// // 1 (index 0 of array1) is smaller than 4 (index 1 of array2)
/// assert_eq!(std::cmp::Ordering::Less, (cmp)(0, 1));
/// # Ok(())
/// # }
/// ```
// This is a factory of comparisons.
// The lifetime 'a enforces that we cannot use the closure beyond any of the array's lifetime.
pub fn build_compare(left: &Array, right: &Array) -> Result<DynComparator> {
    use DataType::*;
    use IntervalUnit::*;
    use TimeUnit::*;
    Ok(match (left.data_type(), right.data_type()) {
        (a, b) if a != b => {
            return Err(ArrowError::InvalidArgumentError(
                "Can't compare arrays of different types".to_string(),
            ));
        }
        (Boolean, Boolean) => compare_boolean(left, right),
        (UInt8, UInt8) => compare_primitives::<UInt8Type>(left, right),
        (UInt16, UInt16) => compare_primitives::<UInt16Type>(left, right),
        (UInt32, UInt32) => compare_primitives::<UInt32Type>(left, right),
        (UInt64, UInt64) => compare_primitives::<UInt64Type>(left, right),
        (Int8, Int8) => compare_primitives::<Int8Type>(left, right),
        (Int16, Int16) => compare_primitives::<Int16Type>(left, right),
        (Int32, Int32) => compare_primitives::<Int32Type>(left, right),
        (Int64, Int64) => compare_primitives::<Int64Type>(left, right),
        (Float32, Float32) => compare_float::<Float32Type>(left, right),
        (Float64, Float64) => compare_float::<Float64Type>(left, right),
        (Date32, Date32) => compare_primitives::<Date32Type>(left, right),
        (Date64, Date64) => compare_primitives::<Date64Type>(left, right),
        (Time32(Second), Time32(Second)) => {
            compare_primitives::<Time32SecondType>(left, right)
        }
        (Time32(Millisecond), Time32(Millisecond)) => {
            compare_primitives::<Time32MillisecondType>(left, right)
        }
        (Time64(Microsecond), Time64(Microsecond)) => {
            compare_primitives::<Time64MicrosecondType>(left, right)
        }
        (Time64(Nanosecond), Time64(Nanosecond)) => {
            compare_primitives::<Time64NanosecondType>(left, right)
        }
        (Timestamp(Second, _), Timestamp(Second, _)) => {
            compare_primitives::<TimestampSecondType>(left, right)
        }
        (Timestamp(Millisecond, _), Timestamp(Millisecond, _)) => {
            compare_primitives::<TimestampMillisecondType>(left, right)
        }
        (Timestamp(Microsecond, _), Timestamp(Microsecond, _)) => {
            compare_primitives::<TimestampMicrosecondType>(left, right)
        }
        (Timestamp(Nanosecond, _), Timestamp(Nanosecond, _)) => {
            compare_primitives::<TimestampNanosecondType>(left, right)
        }
        (Interval(YearMonth), Interval(YearMonth)) => {
            compare_primitives::<IntervalYearMonthType>(left, right)
        }
        (Interval(DayTime), Interval(DayTime)) => {
            compare_primitives::<IntervalDayTimeType>(left, right)
        }
        (Duration(Second), Duration(Second)) => {
            compare_primitives::<DurationSecondType>(left, right)
        }
        (Duration(Millisecond), Duration(Millisecond)) => {
            compare_primitives::<DurationMillisecondType>(left, right)
        }
        (Duration(Microsecond), Duration(Microsecond)) => {
            compare_primitives::<DurationMicrosecondType>(left, right)
        }
        (Duration(Nanosecond), Duration(Nanosecond)) => {
            compare_primitives::<DurationNanosecondType>(left, right)
        }
        (Utf8, Utf8) => compare_string::<i32>(left, right),
        (LargeUtf8, LargeUtf8) => compare_string::<i64>(left, right),
        (
            Dictionary(key_type_lhs, value_type_lhs),
            Dictionary(key_type_rhs, value_type_rhs),
        ) => {
            if value_type_lhs.as_ref() != &DataType::Utf8
                || value_type_rhs.as_ref() != &DataType::Utf8
            {
                return Err(ArrowError::InvalidArgumentError(
                    "Arrow still does not support comparisons of non-string dictionary arrays"
                        .to_string(),
                ));
            }
            match (key_type_lhs.as_ref(), key_type_rhs.as_ref()) {
                (a, b) if a != b => {
                    return Err(ArrowError::InvalidArgumentError(
                        "Can't compare arrays of different types".to_string(),
                    ));
                }
                (UInt8, UInt8) => compare_dict_string::<UInt8Type>(left, right),
                (UInt16, UInt16) => compare_dict_string::<UInt16Type>(left, right),
                (UInt32, UInt32) => compare_dict_string::<UInt32Type>(left, right),
                (UInt64, UInt64) => compare_dict_string::<UInt64Type>(left, right),
                (Int8, Int8) => compare_dict_string::<Int8Type>(left, right),
                (Int16, Int16) => compare_dict_string::<Int16Type>(left, right),
                (Int32, Int32) => compare_dict_string::<Int32Type>(left, right),
                (Int64, Int64) => compare_dict_string::<Int64Type>(left, right),
                (lhs, _) => {
                    return Err(ArrowError::InvalidArgumentError(format!(
                        "Dictionaries do not support keys of type {:?}",
                        lhs
                    )));
                }
            }
        }
        (lhs, _) => {
            return Err(ArrowError::InvalidArgumentError(format!(
                "The data type type {:?} has no natural order",
                lhs
            )));
        }
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::array::{Float64Array, Int32Array};
    use crate::error::Result;
    use std::cmp::Ordering;

    #[test]
    fn test_i32() -> Result<()> {
        let array = Int32Array::from(vec![1, 2]);

        let cmp = build_compare(&array, &array)?;

        assert_eq!(Ordering::Less, (cmp)(0, 1));
        Ok(())
    }

    #[test]
    fn test_i32_i32() -> Result<()> {
        let array1 = Int32Array::from(vec![1]);
        let array2 = Int32Array::from(vec![2]);

        let cmp = build_compare(&array1, &array2)?;

        assert_eq!(Ordering::Less, (cmp)(0, 0));
        Ok(())
    }

    #[test]
    fn test_f64() -> Result<()> {
        let array = Float64Array::from(vec![1.0, 2.0]);

        let cmp = build_compare(&array, &array)?;

        assert_eq!(Ordering::Less, (cmp)(0, 1));
        Ok(())
    }

    #[test]
    fn test_f64_nan() -> Result<()> {
        let array = Float64Array::from(vec![1.0, f64::NAN]);

        let cmp = build_compare(&array, &array)?;

        assert_eq!(Ordering::Less, (cmp)(0, 1));
        Ok(())
    }

    #[test]
    fn test_f64_zeros() -> Result<()> {
        let array = Float64Array::from(vec![-0.0, 0.0]);

        let cmp = build_compare(&array, &array)?;

        assert_eq!(Ordering::Less, (cmp)(0, 1));
        assert_eq!(Ordering::Greater, (cmp)(1, 0));
        Ok(())
    }

    #[test]
    fn test_dict() -> Result<()> {
        let data = vec!["a", "b", "c", "a", "a", "c", "c"];
        let array = data.into_iter().collect::<DictionaryArray<Int16Type>>();

        let cmp = build_compare(&array, &array)?;

        assert_eq!(Ordering::Less, (cmp)(0, 1));
        assert_eq!(Ordering::Equal, (cmp)(3, 4));
        assert_eq!(Ordering::Greater, (cmp)(2, 3));
        Ok(())
    }

    #[test]
    fn test_multiple_dict() -> Result<()> {
        let d1 = vec!["a", "b", "c", "d"];
        let a1 = d1.into_iter().collect::<DictionaryArray<Int16Type>>();
        let d2 = vec!["e", "f", "g", "a"];
        let a2 = d2.into_iter().collect::<DictionaryArray<Int16Type>>();

        let cmp = build_compare(&a1, &a2)?;

        assert_eq!(Ordering::Less, (cmp)(0, 0));
        assert_eq!(Ordering::Equal, (cmp)(0, 3));
        assert_eq!(Ordering::Greater, (cmp)(1, 3));
        Ok(())
    }
}
