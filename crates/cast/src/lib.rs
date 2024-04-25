use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_primitives::{
    utils::{keccak256, ParseUnits, Unit},
    Address, Keccak256, B256, I256, U256,
};
use alloy_rlp::Decodable;
use alloy_sol_types::sol;
use base::{Base, NumberWithBase, ToBase};
use evm_disassembler::{disassemble_str, format_operations};
use eyre::{Context, ContextCompat, Result};
use foundry_common::abi::{encode_function_args, get_func};
use rayon::prelude::*;
use std::{
    str::FromStr,
    sync::atomic::{AtomicBool, Ordering},
};

use foundry_common::abi::encode_function_args_packed;

pub mod base;
pub mod errors;
mod rlp_converter;

use rlp_converter::Item;

// TODO: CastContract with common contract initializers? Same for CastProviders?

sol! {
    #[sol(rpc)]
    interface IERC20 {
        #[derive(Debug)]
        function balanceOf(address owner) external view returns (uint256);
    }
}

pub struct InterfaceSource {
    pub name: String,
    pub json_abi: String,
    pub source: String,
}

// Local is a path to the directory containing the ABI files
// In case of etherscan, ABI is fetched from the address on the chain
pub enum AbiPath {
    Local { path: String, name: Option<String> },
}

pub struct SimpleCast;

impl SimpleCast {
    /// Returns the maximum value of the given integer type
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast;
    /// use ethers_core::types::{I256, U256};
    ///
    /// assert_eq!(SimpleCast::max_int("uint256")?, U256::MAX.to_string());
    /// assert_eq!(SimpleCast::max_int("int256")?, I256::MAX.to_string());
    /// assert_eq!(SimpleCast::max_int("int32")?, i32::MAX.to_string());
    /// # Ok::<(), eyre::Report>(())
    /// ```
    pub fn max_int(s: &str) -> Result<String> {
        Self::max_min_int::<true>(s)
    }

    /// Returns the maximum value of the given integer type
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast;
    /// use ethers_core::types::{I256, U256};
    ///
    /// assert_eq!(SimpleCast::min_int("uint256")?, "0");
    /// assert_eq!(SimpleCast::min_int("int256")?, I256::MIN.to_string());
    /// assert_eq!(SimpleCast::min_int("int32")?, i32::MIN.to_string());
    /// # Ok::<(), eyre::Report>(())
    /// ```
    pub fn min_int(s: &str) -> Result<String> {
        Self::max_min_int::<false>(s)
    }

    fn max_min_int<const MAX: bool>(s: &str) -> Result<String> {
        let ty = DynSolType::parse(s).wrap_err("Invalid type, expected `(u)int<bit size>`")?;
        match ty {
            DynSolType::Int(n) => {
                let mask = U256::from(1).wrapping_shl(n - 1);
                let max = (U256::MAX & mask).saturating_sub(U256::from(1));
                if MAX {
                    Ok(max.to_string())
                } else {
                    let min = I256::from_raw(max).wrapping_neg() + I256::MINUS_ONE;
                    Ok(min.to_string())
                }
            }
            DynSolType::Uint(n) => {
                if MAX {
                    let mut max = U256::MAX;
                    if n < 255 {
                        max &= U256::from(1).wrapping_shl(n);
                    }
                    Ok(max.to_string())
                } else {
                    Ok("0".to_string())
                }
            }
            _ => Err(eyre::eyre!("Type is not int/uint: {s}")),
        }
    }

    /// Converts UTF-8 text input to hex
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(Cast::from_utf8("yo"), "0x796f");
    /// assert_eq!(Cast::from_utf8("Hello, World!"), "0x48656c6c6f2c20576f726c6421");
    /// assert_eq!(Cast::from_utf8("TurboDappTools"), "0x547572626f44617070546f6f6c73");
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn from_utf8(s: &str) -> String {
        hex::encode_prefixed(s)
    }

    /// Converts hex data into text data
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(Cast::to_ascii("0x796f")?, "yo");
    /// assert_eq!(Cast::to_ascii("48656c6c6f2c20576f726c6421")?, "Hello, World!");
    /// assert_eq!(Cast::to_ascii("0x547572626f44617070546f6f6c73")?, "TurboDappTools");
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn to_ascii(hex: &str) -> Result<String> {
        let bytes = hex::decode(hex)?;
        if !bytes.iter().all(u8::is_ascii) {
            return Err(eyre::eyre!("Invalid ASCII bytes"))
        }
        Ok(String::from_utf8(bytes).unwrap())
    }

    /// Converts fixed point number into specified number of decimals
    /// ```
    /// use cast::SimpleCast as Cast;
    /// use ethers_core::types::U256;
    ///
    /// assert_eq!(Cast::from_fixed_point("10", "0")?, "10");
    /// assert_eq!(Cast::from_fixed_point("1.0", "1")?, "10");
    /// assert_eq!(Cast::from_fixed_point("0.10", "2")?, "10");
    /// assert_eq!(Cast::from_fixed_point("0.010", "3")?, "10");
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn from_fixed_point(value: &str, decimals: &str) -> Result<String> {
        // TODO: https://github.com/alloy-rs/core/pull/461
        let units: Unit = if let Ok(x) = decimals.parse() {
            Unit::new(x).ok_or_else(|| eyre::eyre!("invalid unit"))?
        } else {
            decimals.parse()?
        };
        let n = ParseUnits::parse_units(value, units)?;
        Ok(n.to_string())
    }

    /// Converts integers with specified decimals into fixed point numbers
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    /// use ethers_core::types::U256;
    ///
    /// assert_eq!(Cast::to_fixed_point("10", "0")?, "10.");
    /// assert_eq!(Cast::to_fixed_point("10", "1")?, "1.0");
    /// assert_eq!(Cast::to_fixed_point("10", "2")?, "0.10");
    /// assert_eq!(Cast::to_fixed_point("10", "3")?, "0.010");
    ///
    /// assert_eq!(Cast::to_fixed_point("-10", "0")?, "-10.");
    /// assert_eq!(Cast::to_fixed_point("-10", "1")?, "-1.0");
    /// assert_eq!(Cast::to_fixed_point("-10", "2")?, "-0.10");
    /// assert_eq!(Cast::to_fixed_point("-10", "3")?, "-0.010");
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn to_fixed_point(value: &str, decimals: &str) -> Result<String> {
        let (sign, mut value, value_len) = {
            let number = NumberWithBase::parse_int(value, None)?;
            let sign = if number.is_nonnegative() { "" } else { "-" };
            let value = format!("{number:#}");
            let value_stripped = value.strip_prefix('-').unwrap_or(&value).to_string();
            let value_len = value_stripped.len();
            (sign, value_stripped, value_len)
        };
        let decimals = NumberWithBase::parse_uint(decimals, None)?.number().to::<usize>();

        let value = if decimals >= value_len {
            // Add "0." and pad with 0s
            format!("0.{value:0>decimals$}")
        } else {
            // Insert decimal at -idx (i.e 1 => decimal idx = -1)
            value.insert(value_len - decimals, '.');
            value
        };

        Ok(format!("{sign}{value}"))
    }

    /// Concatencates hex strings
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(Cast::concat_hex(["0x00", "0x01"]), "0x0001");
    /// assert_eq!(Cast::concat_hex(["1", "2"]), "0x12");
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn concat_hex<T: AsRef<str>>(values: impl IntoIterator<Item = T>) -> String {
        let mut out = String::new();
        for s in values {
            let s = s.as_ref();
            out.push_str(s.strip_prefix("0x").unwrap_or(s))
        }
        format!("0x{out}")
    }

    /// Converts a number into uint256 hex string with 0x prefix
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(
    ///     Cast::to_uint256("100")?,
    ///     "0x0000000000000000000000000000000000000000000000000000000000000064"
    /// );
    /// assert_eq!(
    ///     Cast::to_uint256("192038293923")?,
    ///     "0x0000000000000000000000000000000000000000000000000000002cb65fd1a3"
    /// );
    /// assert_eq!(
    ///     Cast::to_uint256(
    ///         "115792089237316195423570985008687907853269984665640564039457584007913129639935"
    ///     )?,
    ///     "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    /// );
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn to_uint256(value: &str) -> Result<String> {
        let n = NumberWithBase::parse_uint(value, None)?;
        Ok(format!("{n:#066x}"))
    }

    /// Converts a number into int256 hex string with 0x prefix
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(
    ///     Cast::to_int256("0")?,
    ///     "0x0000000000000000000000000000000000000000000000000000000000000000"
    /// );
    /// assert_eq!(
    ///     Cast::to_int256("100")?,
    ///     "0x0000000000000000000000000000000000000000000000000000000000000064"
    /// );
    /// assert_eq!(
    ///     Cast::to_int256("-100")?,
    ///     "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff9c"
    /// );
    /// assert_eq!(
    ///     Cast::to_int256("192038293923")?,
    ///     "0x0000000000000000000000000000000000000000000000000000002cb65fd1a3"
    /// );
    /// assert_eq!(
    ///     Cast::to_int256("-192038293923")?,
    ///     "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffd349a02e5d"
    /// );
    /// assert_eq!(
    ///     Cast::to_int256(
    ///         "57896044618658097711785492504343953926634992332820282019728792003956564819967"
    ///     )?,
    ///     "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    /// );
    /// assert_eq!(
    ///     Cast::to_int256(
    ///         "-57896044618658097711785492504343953926634992332820282019728792003956564819968"
    ///     )?,
    ///     "0x8000000000000000000000000000000000000000000000000000000000000000"
    /// );
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn to_int256(value: &str) -> Result<String> {
        let n = NumberWithBase::parse_int(value, None)?;
        Ok(format!("{n:#066x}"))
    }

    /// Converts an eth amount into a specified unit
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(Cast::to_unit("1 wei", "wei")?, "1");
    /// assert_eq!(Cast::to_unit("1", "wei")?, "1");
    /// assert_eq!(Cast::to_unit("1ether", "wei")?, "1000000000000000000");
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn to_unit(value: &str, unit: &str) -> Result<String> {
        let value = DynSolType::coerce_str(&DynSolType::Uint(256), value)?
            .as_uint()
            .wrap_err("Could not convert to uint")?
            .0;
        let unit = unit.parse().wrap_err("could not parse units")?;
        let mut formatted = ParseUnits::U256(value).format_units(unit);

        // Trim empty fractional part.
        if let Some(dot) = formatted.find('.') {
            let fractional = &formatted[dot + 1..];
            if fractional.chars().all(|c: char| c == '0') {
                formatted = formatted[..dot].to_string();
            }
        }

        Ok(formatted)
    }

    /// Converts wei into an eth amount
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(Cast::from_wei("1", "gwei")?, "0.000000001");
    /// assert_eq!(Cast::from_wei("12340000005", "gwei")?, "12.340000005");
    /// assert_eq!(Cast::from_wei("10", "ether")?, "0.000000000000000010");
    /// assert_eq!(Cast::from_wei("100", "eth")?, "0.000000000000000100");
    /// assert_eq!(Cast::from_wei("17", "ether")?, "0.000000000000000017");
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn from_wei(value: &str, unit: &str) -> Result<String> {
        let value = NumberWithBase::parse_int(value, None)?.number();
        Ok(ParseUnits::U256(value).format_units(unit.parse()?))
    }

    /// Converts an eth amount into wei
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(Cast::to_wei("100", "gwei")?, "100000000000");
    /// assert_eq!(Cast::to_wei("100", "eth")?, "100000000000000000000");
    /// assert_eq!(Cast::to_wei("1000", "ether")?, "1000000000000000000000");
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn to_wei(value: &str, unit: &str) -> Result<String> {
        let unit = unit.parse().wrap_err("could not parse units")?;
        Ok(ParseUnits::parse_units(value, unit)?.to_string())
    }

    /// Decodes rlp encoded list with hex data
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(Cast::from_rlp("0xc0").unwrap(), "[]");
    /// assert_eq!(Cast::from_rlp("0x0f").unwrap(), "\"0x0f\"");
    /// assert_eq!(Cast::from_rlp("0x33").unwrap(), "\"0x33\"");
    /// assert_eq!(Cast::from_rlp("0xc161").unwrap(), "[\"0x61\"]");
    /// assert_eq!(Cast::from_rlp("0xc26162").unwrap(), "[\"0x61\",\"0x62\"]");
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn from_rlp(value: impl AsRef<str>) -> Result<String> {
        let bytes = hex::decode(value.as_ref()).wrap_err("Could not decode hex")?;
        let item = Item::decode(&mut &bytes[..]).wrap_err("Could not decode rlp")?;
        Ok(item.to_string())
    }

    /// Encodes hex data or list of hex data to hexadecimal rlp
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(Cast::to_rlp("[]").unwrap(), "0xc0".to_string());
    /// assert_eq!(Cast::to_rlp("0x22").unwrap(), "0x22".to_string());
    /// assert_eq!(Cast::to_rlp("[\"0x61\"]",).unwrap(), "0xc161".to_string());
    /// assert_eq!(Cast::to_rlp("[\"0xf1\",\"f2\"]").unwrap(), "0xc481f181f2".to_string());
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn to_rlp(value: &str) -> Result<String> {
        let val = serde_json::from_str(value)
            .unwrap_or_else(|_| serde_json::Value::String(value.to_string()));
        let item = Item::value_to_item(&val)?;
        Ok(format!("0x{}", hex::encode(alloy_rlp::encode(item))))
    }

    /// Converts a number of one base to another
    ///
    /// # Example
    ///
    /// ```
    /// use alloy_primitives::I256;
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(Cast::to_base("100", Some("10"), "16")?, "0x64");
    /// assert_eq!(Cast::to_base("100", Some("10"), "oct")?, "0o144");
    /// assert_eq!(Cast::to_base("100", Some("10"), "binary")?, "0b1100100");
    ///
    /// assert_eq!(Cast::to_base("0xffffffffffffffff", None, "10")?, u64::MAX.to_string());
    /// assert_eq!(
    ///     Cast::to_base("0xffffffffffffffffffffffffffffffff", None, "dec")?,
    ///     u128::MAX.to_string()
    /// );
    /// // U256::MAX overflows as internally it is being parsed as I256
    /// assert_eq!(
    ///     Cast::to_base(
    ///         "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ///         None,
    ///         "decimal"
    ///     )?,
    ///     I256::MAX.to_string()
    /// );
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn to_base(value: &str, base_in: Option<&str>, base_out: &str) -> Result<String> {
        let base_in = Base::unwrap_or_detect(base_in, value)?;
        let base_out: Base = base_out.parse()?;
        if base_in == base_out {
            return Ok(value.to_string())
        }

        let mut n = NumberWithBase::parse_int(value, Some(&base_in.to_string()))?;
        n.set_base(base_out);

        // Use Debug fmt
        Ok(format!("{n:#?}"))
    }

    /// Converts hexdata into bytes32 value
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// let bytes = Cast::to_bytes32("1234")?;
    /// assert_eq!(bytes, "0x1234000000000000000000000000000000000000000000000000000000000000");
    ///
    /// let bytes = Cast::to_bytes32("0x1234")?;
    /// assert_eq!(bytes, "0x1234000000000000000000000000000000000000000000000000000000000000");
    ///
    /// let err = Cast::to_bytes32("0x123400000000000000000000000000000000000000000000000000000000000011").unwrap_err();
    /// assert_eq!(err.to_string(), "string >32 bytes");
    /// # Ok::<_, eyre::Report>(())
    pub fn to_bytes32(s: &str) -> Result<String> {
        let s = strip_0x(s);
        if s.len() > 64 {
            eyre::bail!("string >32 bytes");
        }

        let padded = format!("{s:0<64}");
        Ok(padded.parse::<B256>()?.to_string())
    }

    /// Encodes string into bytes32 value
    pub fn format_bytes32_string(s: &str) -> Result<String> {
        let str_bytes: &[u8] = s.as_bytes();
        eyre::ensure!(str_bytes.len() <= 32, "bytes32 strings must not exceed 32 bytes in length");

        let mut bytes32: [u8; 32] = [0u8; 32];
        bytes32[..str_bytes.len()].copy_from_slice(str_bytes);
        Ok(hex::encode_prefixed(bytes32))
    }

    /// Decodes string from bytes32 value
    pub fn parse_bytes32_string(s: &str) -> Result<String> {
        let bytes = hex::decode(s)?;
        eyre::ensure!(bytes.len() == 32, "expected 32 byte hex-string");
        let len = bytes.iter().take_while(|x| **x != 0).count();
        Ok(std::str::from_utf8(&bytes[..len])?.into())
    }

    /// Decodes checksummed address from bytes32 value
    pub fn parse_bytes32_address(s: &str) -> Result<String> {
        let s = strip_0x(s);
        if s.len() != 64 {
            eyre::bail!("expected 64 byte hex-string, got {s}");
        }

        let s = if let Some(stripped) = s.strip_prefix("000000000000000000000000") {
            stripped
        } else {
            return Err(eyre::eyre!("Not convertible to address, there are non-zero bytes"))
        };

        let lowercase_address_string = format!("0x{s}");
        let lowercase_address = Address::from_str(&lowercase_address_string)?;

        Ok(lowercase_address.to_checksum(None))
    }

    /// Decodes abi-encoded hex input or output
    ///
    /// When `input=true`, `calldata` string MUST not be prefixed with function selector
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    /// use hex;
    ///
    ///     // Passing `input = false` will decode the data as the output type.
    ///     // The input data types and the full function sig are ignored, i.e.
    ///     // you could also pass `balanceOf()(uint256)` and it'd still work.
    ///     let data = "0x0000000000000000000000000000000000000000000000000000000000000001";
    ///     let sig = "balanceOf(address, uint256)(uint256)";
    ///     let decoded = Cast::abi_decode(sig, data, false)?[0].as_uint().unwrap().0.to_string();
    ///     assert_eq!(decoded, "1");
    ///
    ///     // Passing `input = true` will decode the data with the input function signature.
    ///     // We exclude the "prefixed" function selector from the data field (the first 4 bytes).
    ///     let data = "0x0000000000000000000000008dbd1b711dc621e1404633da156fcc779e1c6f3e000000000000000000000000d9f3c9cc99548bf3b44a43e0a2d07399eb918adc000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000";
    ///     let sig = "safeTransferFrom(address, address, uint256, uint256, bytes)";
    ///     let decoded = Cast::abi_decode(sig, data, true)?;
    ///     let decoded = [
    ///         decoded[0].as_address().unwrap().to_string().to_lowercase(),
    ///         decoded[1].as_address().unwrap().to_string().to_lowercase(),
    ///         decoded[2].as_uint().unwrap().0.to_string(),
    ///         decoded[3].as_uint().unwrap().0.to_string(),
    ///         hex::encode(decoded[4].as_bytes().unwrap())    
    ///     ]
    ///     .into_iter()
    ///     .collect::<Vec<_>>();
    ///
    ///     assert_eq!(
    ///         decoded,
    ///         vec!["0x8dbd1b711dc621e1404633da156fcc779e1c6f3e", "0xd9f3c9cc99548bf3b44a43e0a2d07399eb918adc", "42", "1", ""]
    ///     );
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn abi_decode(sig: &str, calldata: &str, input: bool) -> Result<Vec<DynSolValue>> {
        foundry_common::abi::abi_decode_calldata(sig, calldata, input, false)
    }

    /// Decodes calldata-encoded hex input or output
    ///
    /// Similar to `abi_decode`, but `calldata` string MUST be prefixed with function selector
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// // Passing `input = false` will decode the data as the output type.
    /// // The input data types and the full function sig are ignored, i.e.
    /// // you could also pass `balanceOf()(uint256)` and it'd still work.
    /// let data = "0x0000000000000000000000000000000000000000000000000000000000000001";
    /// let sig = "balanceOf(address, uint256)(uint256)";
    /// let decoded = Cast::calldata_decode(sig, data, false)?[0].as_uint().unwrap().0.to_string();
    /// assert_eq!(decoded, "1");
    ///
    ///     // Passing `input = true` will decode the data with the input function signature.
    ///     let data = "0xf242432a0000000000000000000000008dbd1b711dc621e1404633da156fcc779e1c6f3e000000000000000000000000d9f3c9cc99548bf3b44a43e0a2d07399eb918adc000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000";
    ///     let sig = "safeTransferFrom(address, address, uint256, uint256, bytes)";
    ///     let decoded = Cast::calldata_decode(sig, data, true)?;
    ///     let decoded = [
    ///         decoded[0].as_address().unwrap().to_string().to_lowercase(),
    ///         decoded[1].as_address().unwrap().to_string().to_lowercase(),
    ///         decoded[2].as_uint().unwrap().0.to_string(),
    ///         decoded[3].as_uint().unwrap().0.to_string(),
    ///         hex::encode(decoded[4].as_bytes().unwrap()),
    ///    ]
    ///    .into_iter()
    ///    .collect::<Vec<_>>();
    ///     assert_eq!(
    ///         decoded,
    ///         vec!["0x8dbd1b711dc621e1404633da156fcc779e1c6f3e", "0xd9f3c9cc99548bf3b44a43e0a2d07399eb918adc", "42", "1", ""]
    ///     );
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn calldata_decode(sig: &str, calldata: &str, input: bool) -> Result<Vec<DynSolValue>> {
        foundry_common::abi::abi_decode_calldata(sig, calldata, input, true)
    }

    /// Performs ABI encoding based off of the function signature. Does not include
    /// the function selector in the result.
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(
    ///     "0x0000000000000000000000000000000000000000000000000000000000000001",
    ///     Cast::abi_encode("f(uint a)", &["1"]).unwrap().as_str()
    /// );
    /// assert_eq!(
    ///     "0x0000000000000000000000000000000000000000000000000000000000000001",
    ///     Cast::abi_encode("constructor(uint a)", &["1"]).unwrap().as_str()
    /// );
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn abi_encode(sig: &str, args: &[impl AsRef<str>]) -> Result<String> {
        let func = get_func(sig)?;
        let calldata = match encode_function_args(&func, args) {
            Ok(res) => hex::encode(res),
            Err(e) => eyre::bail!("Could not ABI encode the function and arguments. Did you pass in the right types?\nError\n{}", e),
        };
        let encoded = &calldata[8..];
        Ok(format!("0x{encoded}"))
    }

    /// Performs packed ABI encoding based off of the function signature or tuple.
    ///
    /// # Examplez
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(
    ///     "0x0000000000000000000000000000000000000000000000000000000000000064000000000000000000000000000000000000000000000000000000000000012c00000000000000c8",
    ///     Cast::abi_encode_packed("(uint128[] a, uint64 b)", &["[100, 300]", "200"]).unwrap().as_str()
    /// );
    ///
    /// assert_eq!(
    ///     "0x8dbd1b711dc621e1404633da156fcc779e1c6f3e68656c6c6f20776f726c64",
    ///     Cast::abi_encode_packed("foo(address a, string b)", &["0x8dbd1b711dc621e1404633da156fcc779e1c6f3e", "hello world"]).unwrap().as_str()
    /// );
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn abi_encode_packed(sig: &str, args: &[impl AsRef<str>]) -> Result<String> {
        // If the signature is a tuple, we need to prefix it to make it a function
        let sig =
            if sig.trim_start().starts_with('(') { format!("foo{sig}") } else { sig.to_string() };

        let func = get_func(sig.as_str())?;
        let encoded = match encode_function_args_packed(&func, args) {
            Ok(res) => hex::encode(res),
            Err(e) => eyre::bail!("Could not ABI encode the function and arguments. Did you pass in the right types?\nError\n{}", e),
        };
        Ok(format!("0x{encoded}"))
    }

    /// Performs ABI encoding to produce the hexadecimal calldata with the given arguments.
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(
    ///     "0xb3de648b0000000000000000000000000000000000000000000000000000000000000001",
    ///     Cast::calldata_encode("f(uint256 a)", &["1"]).unwrap().as_str()
    /// );
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn calldata_encode(sig: impl AsRef<str>, args: &[impl AsRef<str>]) -> Result<String> {
        let func = get_func(sig.as_ref())?;
        let calldata = encode_function_args(&func, args)?;
        Ok(hex::encode_prefixed(calldata))
    }

    /// Prints the slot number for the specified mapping type and input data.
    ///
    /// For value types `v`, slot number of `v` is `keccak256(concat(h(v), p))` where `h` is the
    /// padding function for `v`'s type, and `p` is slot number of the mapping.
    ///
    /// See [the Solidity documentation](https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html#mappings-and-dynamic-arrays)
    /// for more details.
    ///
    /// # Example
    ///
    /// ```
    /// # use cast::SimpleCast as Cast;
    ///
    /// // Value types.
    /// assert_eq!(
    ///     Cast::index("address", "0xD0074F4E6490ae3f888d1d4f7E3E43326bD3f0f5", "2").unwrap().as_str(),
    ///     "0x9525a448a9000053a4d151336329d6563b7e80b24f8e628e95527f218e8ab5fb"
    /// );
    /// assert_eq!(
    ///     Cast::index("uint256", "42", "6").unwrap().as_str(),
    ///     "0xfc808b0f31a1e6b9cf25ff6289feae9b51017b392cc8e25620a94a38dcdafcc1"
    /// );
    ///
    /// // Strings and byte arrays.
    /// assert_eq!(
    ///     Cast::index("string", "hello", "1").unwrap().as_str(),
    ///     "0x8404bb4d805e9ca2bd5dd5c43a107e935c8ec393caa7851b353b3192cd5379ae"
    /// );
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn index(from_type: &str, from_value: &str, slot_number: &str) -> Result<String> {
        let mut hasher = Keccak256::new();

        let v_ty = DynSolType::parse(from_type).wrap_err("Could not parse type")?;
        let v = v_ty.coerce_str(from_value).wrap_err("Could not parse value")?;
        match v_ty {
            // For value types, `h` pads the value to 32 bytes in the same way as when storing the
            // value in memory.
            DynSolType::Bool |
            DynSolType::Int(_) |
            DynSolType::Uint(_) |
            DynSolType::FixedBytes(_) |
            DynSolType::Address |
            DynSolType::Function => hasher.update(v.as_word().unwrap()),

            // For strings and byte arrays, `h(k)` is just the unpadded data.
            DynSolType::String | DynSolType::Bytes => hasher.update(v.as_packed_seq().unwrap()),

            DynSolType::Array(..) |
            DynSolType::FixedArray(..) |
            DynSolType::Tuple(..) |
            DynSolType::CustomStruct { .. } => {
                eyre::bail!("Type `{v_ty}` is not supported as a mapping key")
            }
        }

        let p = DynSolType::Uint(256)
            .coerce_str(slot_number)
            .wrap_err("Could not parse slot number")?;
        let p = p.as_word().unwrap();
        hasher.update(p);

        let location = hasher.finalize();
        Ok(location.to_string())
    }

    /// Converts ENS names to their namehash representation
    /// [Namehash reference](https://docs.ens.domains/contract-api-reference/name-processing#hashing-names)
    /// [namehash-rust reference](https://github.com/InstateDev/namehash-rust/blob/master/src/lib.rs)
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(
    ///     Cast::namehash("")?,
    ///     "0x0000000000000000000000000000000000000000000000000000000000000000"
    /// );
    /// assert_eq!(
    ///     Cast::namehash("eth")?,
    ///     "0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"
    /// );
    /// assert_eq!(
    ///     Cast::namehash("foo.eth")?,
    ///     "0xde9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f"
    /// );
    /// assert_eq!(
    ///     Cast::namehash("sub.foo.eth")?,
    ///     "0x500d86f9e663479e5aaa6e99276e55fc139c597211ee47d17e1e92da16a83402"
    /// );
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn namehash(ens: &str) -> Result<String> {
        let mut node = vec![0u8; 32];

        if !ens.is_empty() {
            let ens_lower = ens.to_lowercase();
            let mut labels: Vec<&str> = ens_lower.split('.').collect();
            labels.reverse();

            for label in labels {
                let mut label_hash = keccak256(label.as_bytes());
                node.append(&mut label_hash.to_vec());

                label_hash = keccak256(node.as_slice());
                node = label_hash.to_vec();
            }
        }

        Ok(hex::encode_prefixed(node))
    }

    /// Keccak-256 hashes arbitrary data
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(
    ///     Cast::keccak("foo")?,
    ///     "0x41b1a0649752af1b28b3dc29a1556eee781e4a4c3a1f7f53f90fa834de098c4d"
    /// );
    /// assert_eq!(
    ///     Cast::keccak("123abc")?,
    ///     "0xb1f1c74a1ba56f07a892ea1110a39349d40f66ca01d245e704621033cb7046a4"
    /// );
    /// assert_eq!(
    ///     Cast::keccak("0x12")?,
    ///     "0x5fa2358263196dbbf23d1ca7a509451f7a2f64c15837bfbb81298b1e3e24e4fa"
    /// );
    /// assert_eq!(
    ///     Cast::keccak("12")?,
    ///     "0x7f8b6b088b6d74c2852fc86c796dca07b44eed6fb3daf5e6b59f7c364db14528"
    /// );
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn keccak(data: &str) -> Result<String> {
        // Hex-decode if data starts with 0x.
        let hash =
            if data.starts_with("0x") { keccak256(hex::decode(data)?) } else { keccak256(data) };
        Ok(hash.to_string())
    }

    /// Performs the left shift operation (<<) on a number
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(Cast::left_shift("16", "10", Some("10"), "hex")?, "0x4000");
    /// assert_eq!(Cast::left_shift("255", "16", Some("dec"), "hex")?, "0xff0000");
    /// assert_eq!(Cast::left_shift("0xff", "16", None, "hex")?, "0xff0000");
    /// # Ok::<_, eyre::Report>(())
    /// ```
    pub fn left_shift(
        value: &str,
        bits: &str,
        base_in: Option<&str>,
        base_out: &str,
    ) -> Result<String> {
        let base_out: Base = base_out.parse()?;
        let value = NumberWithBase::parse_uint(value, base_in)?;
        let bits = NumberWithBase::parse_uint(bits, None)?;

        let res = value.number() << bits.number();

        Ok(res.to_base(base_out, true)?)
    }

    /// Performs the right shift operation (>>) on a number
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(Cast::right_shift("0x4000", "10", None, "dec")?, "16");
    /// assert_eq!(Cast::right_shift("16711680", "16", Some("10"), "hex")?, "0xff");
    /// assert_eq!(Cast::right_shift("0xff0000", "16", None, "hex")?, "0xff");
    /// # Ok::<(), eyre::Report>(())
    /// ```
    pub fn right_shift(
        value: &str,
        bits: &str,
        base_in: Option<&str>,
        base_out: &str,
    ) -> Result<String> {
        let base_out: Base = base_out.parse()?;
        let value = NumberWithBase::parse_uint(value, base_in)?;
        let bits = NumberWithBase::parse_uint(bits, None)?;

        let res = value.number().wrapping_shr(bits.number().saturating_to());

        Ok(res.to_base(base_out, true)?)
    }

    /// Disassembles hex encoded bytecode into individual / human readable opcodes
    ///
    /// # Example
    ///
    /// ```ignore
    /// use cast::SimpleCast as Cast;
    ///
    /// # async fn foo() -> eyre::Result<()> {
    /// let bytecode = "0x608060405260043610603f57600035";
    /// let opcodes = Cast::disassemble(bytecode)?;
    /// println!("{}", opcodes);
    /// # Ok(())
    /// # }
    /// ```
    pub fn disassemble(bytecode: &str) -> Result<String> {
        format_operations(disassemble_str(bytecode)?)
    }

    /// Gets the selector for a given function signature
    /// Optimizes if the `optimize` parameter is set to a number of leading zeroes
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// assert_eq!(Cast::get_selector("foo(address,uint256)", 0)?.0, String::from("0xbd0d639f"));
    /// # Ok::<(), eyre::Error>(())
    /// ```
    pub fn get_selector(signature: &str, optimize: usize) -> Result<(String, String)> {
        if optimize > 4 {
            eyre::bail!("number of leading zeroes must not be greater than 4");
        }
        if optimize == 0 {
            let selector = get_func(signature)?.selector();
            return Ok((selector.to_string(), String::from(signature)))
        }
        let Some((name, params)) = signature.split_once('(') else {
            eyre::bail!("invalid function signature");
        };

        let num_threads = std::thread::available_parallelism().map_or(1, |n| n.get());
        let found = AtomicBool::new(false);

        let result: Option<(u32, String, String)> =
            (0..num_threads).into_par_iter().find_map_any(|i| {
                let nonce_start = i as u32;
                let nonce_step = num_threads as u32;

                let mut nonce = nonce_start;
                while nonce < u32::MAX && !found.load(Ordering::Relaxed) {
                    let input = format!("{}{}({}", name, nonce, params);
                    let hash = keccak256(input.as_bytes());
                    let selector = &hash[..4];

                    if selector.iter().take_while(|&&byte| byte == 0).count() == optimize {
                        found.store(true, Ordering::Relaxed);
                        return Some((nonce, hex::encode_prefixed(selector), input))
                    }

                    nonce += nonce_step;
                }
                None
            });

        match result {
            Some((_nonce, selector, signature)) => Ok((selector, signature)),
            None => eyre::bail!("No selector found"),
        }
    }

    /// Extracts function selectors and arguments from bytecode
    ///
    /// # Example
    ///
    /// ```
    /// use cast::SimpleCast as Cast;
    ///
    /// let bytecode = "6080604052348015600e575f80fd5b50600436106026575f3560e01c80632125b65b14602a575b5f80fd5b603a6035366004603c565b505050565b005b5f805f60608486031215604d575f80fd5b833563ffffffff81168114605f575f80fd5b925060208401356001600160a01b03811681146079575f80fd5b915060408401356001600160e01b03811681146093575f80fd5b80915050925092509256";
    /// let selectors = Cast::extract_selectors(bytecode)?;
    /// assert_eq!(selectors, vec![("0x2125b65b".to_string(), "uint32,address,uint224".to_string())]);
    /// # Ok::<(), eyre::Report>(())
    /// ```
    pub fn extract_selectors(bytecode: &str) -> Result<Vec<(String, String)>> {
        let code = hex::decode(strip_0x(bytecode))?;
        let s = evmole::function_selectors(&code, 0);

        Ok(s.iter()
            .map(|s| (hex::encode_prefixed(s), evmole::function_arguments(&code, s, 0)))
            .collect())
    }

}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::SimpleCast as Cast;
    use alloy_primitives::hex;

    #[test]
    fn simple_selector() {
        assert_eq!("0xc2985578", Cast::get_selector("foo()", 0).unwrap().0.as_str())
    }

    #[test]
    fn selector_with_arg() {
        assert_eq!("0xbd0d639f", Cast::get_selector("foo(address,uint256)", 0).unwrap().0.as_str())
    }

    #[test]
    fn calldata_uint() {
        assert_eq!(
            "0xb3de648b0000000000000000000000000000000000000000000000000000000000000001",
            Cast::calldata_encode("f(uint256 a)", &["1"]).unwrap().as_str()
        );
    }

    // <https://github.com/foundry-rs/foundry/issues/2681>
    #[test]
    fn calldata_array() {
        assert_eq!(
            "0xcde2baba0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000",
            Cast::calldata_encode("propose(string[])", &["[\"\"]"]).unwrap().as_str()
        );
    }

    #[test]
    fn calldata_bool() {
        assert_eq!(
            "0x6fae94120000000000000000000000000000000000000000000000000000000000000000",
            Cast::calldata_encode("bar(bool)", &["false"]).unwrap().as_str()
        );
    }

    #[test]
    fn abi_decode() {
        let data = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let sig = "balanceOf(address, uint256)(uint256)";
        assert_eq!(
            "1",
            Cast::abi_decode(sig, data, false).unwrap()[0].as_uint().unwrap().0.to_string()
        );

        let data = "0x0000000000000000000000008dbd1b711dc621e1404633da156fcc779e1c6f3e000000000000000000000000d9f3c9cc99548bf3b44a43e0a2d07399eb918adc000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000";
        let sig = "safeTransferFrom(address,address,uint256,uint256,bytes)";
        let decoded = Cast::abi_decode(sig, data, true).unwrap();
        let decoded = [
            decoded[0]
                .as_address()
                .unwrap()
                .to_string()
                .strip_prefix("0x")
                .unwrap()
                .to_owned()
                .to_lowercase(),
            decoded[1]
                .as_address()
                .unwrap()
                .to_string()
                .strip_prefix("0x")
                .unwrap()
                .to_owned()
                .to_lowercase(),
            decoded[2].as_uint().unwrap().0.to_string(),
            decoded[3].as_uint().unwrap().0.to_string(),
            hex::encode(decoded[4].as_bytes().unwrap()),
        ]
        .to_vec();
        assert_eq!(
            decoded,
            vec![
                "8dbd1b711dc621e1404633da156fcc779e1c6f3e",
                "d9f3c9cc99548bf3b44a43e0a2d07399eb918adc",
                "42",
                "1",
                ""
            ]
        );
    }

    #[test]
    fn calldata_decode() {
        let data = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let sig = "balanceOf(address, uint256)(uint256)";
        let decoded =
            Cast::calldata_decode(sig, data, false).unwrap()[0].as_uint().unwrap().0.to_string();
        assert_eq!(decoded, "1");

        // Passing `input = true` will decode the data with the input function signature.
        // We exclude the "prefixed" function selector from the data field (the first 4 bytes).
        let data = "0xf242432a0000000000000000000000008dbd1b711dc621e1404633da156fcc779e1c6f3e000000000000000000000000d9f3c9cc99548bf3b44a43e0a2d07399eb918adc000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000";
        let sig = "safeTransferFrom(address, address, uint256, uint256, bytes)";
        let decoded = Cast::calldata_decode(sig, data, true).unwrap();
        let decoded = [
            decoded[0].as_address().unwrap().to_string().to_lowercase(),
            decoded[1].as_address().unwrap().to_string().to_lowercase(),
            decoded[2].as_uint().unwrap().0.to_string(),
            decoded[3].as_uint().unwrap().0.to_string(),
            hex::encode(decoded[4].as_bytes().unwrap()),
        ]
        .into_iter()
        .collect::<Vec<_>>();
        assert_eq!(
            decoded,
            vec![
                "0x8dbd1b711dc621e1404633da156fcc779e1c6f3e",
                "0xd9f3c9cc99548bf3b44a43e0a2d07399eb918adc",
                "42",
                "1",
                ""
            ]
        );
    }

    #[test]
    fn concat_hex() {
        assert_eq!(Cast::concat_hex(["0x00", "0x01"]), "0x0001");
        assert_eq!(Cast::concat_hex(["1", "2"]), "0x12");
    }

    #[test]
    fn from_rlp() {
        let rlp = "0xf8b1a02b5df5f0757397573e8ff34a8b987b21680357de1f6c8d10273aa528a851eaca8080a02838ac1d2d2721ba883169179b48480b2ba4f43d70fcf806956746bd9e83f90380a0e46fff283b0ab96a32a7cc375cecc3ed7b6303a43d64e0a12eceb0bc6bd8754980a01d818c1c414c665a9c9a0e0c0ef1ef87cacb380b8c1f6223cb2a68a4b2d023f5808080a0236e8f61ecde6abfebc6c529441f782f62469d8a2cc47b7aace2c136bd3b1ff08080808080";
        let item = Cast::from_rlp(rlp).unwrap();
        assert_eq!(
            item,
            r#"["0x2b5df5f0757397573e8ff34a8b987b21680357de1f6c8d10273aa528a851eaca","0x","0x","0x2838ac1d2d2721ba883169179b48480b2ba4f43d70fcf806956746bd9e83f903","0x","0xe46fff283b0ab96a32a7cc375cecc3ed7b6303a43d64e0a12eceb0bc6bd87549","0x","0x1d818c1c414c665a9c9a0e0c0ef1ef87cacb380b8c1f6223cb2a68a4b2d023f5","0x","0x","0x","0x236e8f61ecde6abfebc6c529441f782f62469d8a2cc47b7aace2c136bd3b1ff0","0x","0x","0x","0x","0x"]"#
        )
    }
}
