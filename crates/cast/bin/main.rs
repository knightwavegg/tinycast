#[macro_use]
extern crate tracing;

use alloy_primitives::{keccak256, Address, B256};
use cast::SimpleCast;
use clap::Parser;
use eyre::Result;
use foundry_cli::{handler, prompt, stdin, utils};
use foundry_common::{
    abi::get_event,
    fs,
    fmt::*,
    selectors::{
        decode_calldata, decode_event_topic, decode_function_selector, decode_selectors,
        pretty_calldata,
        SelectorType,
    },
};
use std::time::Instant;

pub mod cmd;
pub mod opts;

use opts::{Cast as Opts, CastSubcommand, ToBaseArgs};

#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[tokio::main]
async fn main() -> Result<()> {
    handler::install();
    utils::enable_paint();

    let opts = Opts::parse();
    match opts.cmd {
        // Constants
        CastSubcommand::MaxInt { r#type } => {
            println!("{}", SimpleCast::max_int(&r#type)?);
        }
        CastSubcommand::MinInt { r#type } => {
            println!("{}", SimpleCast::min_int(&r#type)?);
        }
        CastSubcommand::MaxUint { r#type } => {
            println!("{}", SimpleCast::max_int(&r#type)?);
        }
        CastSubcommand::AddressZero => {
            println!("{:?}", Address::ZERO);
        }
        CastSubcommand::HashZero => {
            println!("{:?}", B256::ZERO);
        }

        // Conversions & transformations
        CastSubcommand::FromUtf8 { text } => {
            let value = stdin::unwrap(text, false)?;
            println!("{}", SimpleCast::from_utf8(&value));
        }
        CastSubcommand::ToAscii { hexdata } => {
            let value = stdin::unwrap(hexdata, false)?;
            println!("{}", SimpleCast::to_ascii(&value)?);
        }
        CastSubcommand::FromFixedPoint { value, decimals } => {
            let (value, decimals) = stdin::unwrap2(value, decimals)?;
            println!("{}", SimpleCast::from_fixed_point(&value, &decimals)?);
        }
        CastSubcommand::ToFixedPoint { value, decimals } => {
            let (value, decimals) = stdin::unwrap2(value, decimals)?;
            println!("{}", SimpleCast::to_fixed_point(&value, &decimals)?);
        }
        CastSubcommand::ConcatHex { data } => {
            if data.is_empty() {
                let s = stdin::read(true)?;
                println!("{}", SimpleCast::concat_hex(s.split_whitespace()))
            } else {
                println!("{}", SimpleCast::concat_hex(data))
            }
        }
        CastSubcommand::FromBin => {
            let hex = stdin::read_bytes(false)?;
            println!("{}", hex::encode_prefixed(hex));
        }
        CastSubcommand::ToHexdata { input } => {
            let value = stdin::unwrap_line(input)?;
            let output = match value {
                s if s.starts_with('@') => hex::encode(std::env::var(&s[1..])?),
                s if s.starts_with('/') => hex::encode(fs::read(s)?),
                s => s.split(':').map(|s| s.trim_start_matches("0x").to_lowercase()).collect(),
            };
            println!("0x{output}");
        }
        CastSubcommand::ToCheckSumAddress { address } => {
            let value = stdin::unwrap_line(address)?;
            println!("{}", value.to_checksum(None));
        }
        CastSubcommand::ToUint256 { value } => {
            let value = stdin::unwrap_line(value)?;
            println!("{}", SimpleCast::to_uint256(&value)?);
        }
        CastSubcommand::ToInt256 { value } => {
            let value = stdin::unwrap_line(value)?;
            println!("{}", SimpleCast::to_int256(&value)?);
        }
        CastSubcommand::ToUnit { value, unit } => {
            let value = stdin::unwrap_line(value)?;
            println!("{}", SimpleCast::to_unit(&value, &unit)?);
        }
        CastSubcommand::FromWei { value, unit } => {
            let value = stdin::unwrap_line(value)?;
            println!("{}", SimpleCast::from_wei(&value, &unit)?);
        }
        CastSubcommand::ToWei { value, unit } => {
            let value = stdin::unwrap_line(value)?;
            println!("{}", SimpleCast::to_wei(&value, &unit)?);
        }
        CastSubcommand::FromRlp { value } => {
            let value = stdin::unwrap_line(value)?;
            println!("{}", SimpleCast::from_rlp(value)?);
        }
        CastSubcommand::ToRlp { value } => {
            let value = stdin::unwrap_line(value)?;
            println!("{}", SimpleCast::to_rlp(&value)?);
        }
        CastSubcommand::ToHex(ToBaseArgs { value, base_in }) => {
            let value = stdin::unwrap_line(value)?;
            println!("{}", SimpleCast::to_base(&value, base_in.as_deref(), "hex")?);
        }
        CastSubcommand::ToDec(ToBaseArgs { value, base_in }) => {
            let value = stdin::unwrap_line(value)?;
            println!("{}", SimpleCast::to_base(&value, base_in.as_deref(), "dec")?);
        }
        CastSubcommand::ToBase { base: ToBaseArgs { value, base_in }, base_out } => {
            let (value, base_out) = stdin::unwrap2(value, base_out)?;
            println!("{}", SimpleCast::to_base(&value, base_in.as_deref(), &base_out)?);
        }
        CastSubcommand::ToBytes32 { bytes } => {
            let value = stdin::unwrap_line(bytes)?;
            println!("{}", SimpleCast::to_bytes32(&value)?);
        }
        CastSubcommand::FormatBytes32String { string } => {
            let value = stdin::unwrap_line(string)?;
            println!("{}", SimpleCast::format_bytes32_string(&value)?);
        }
        CastSubcommand::ParseBytes32String { bytes } => {
            let value = stdin::unwrap_line(bytes)?;
            println!("{}", SimpleCast::parse_bytes32_string(&value)?);
        }
        CastSubcommand::ParseBytes32Address { bytes } => {
            let value = stdin::unwrap_line(bytes)?;
            println!("{}", SimpleCast::parse_bytes32_address(&value)?);
        }

        // ABI encoding & decoding
        CastSubcommand::AbiDecode { sig, calldata, input } => {
            let tokens = SimpleCast::abi_decode(&sig, &calldata, input)?;
            let tokens = format_tokens(&tokens);
            tokens.for_each(|t| println!("{t}"));
        }
        CastSubcommand::AbiEncode { sig, packed, args } => {
            if !packed {
                println!("{}", SimpleCast::abi_encode(&sig, &args)?);
            } else {
                println!("{}", SimpleCast::abi_encode_packed(&sig, &args)?);
            }
        }
        CastSubcommand::CalldataDecode { sig, calldata } => {
            let tokens = SimpleCast::calldata_decode(&sig, &calldata, true)?;
            let tokens = format_tokens(&tokens);
            tokens.for_each(|t| println!("{t}"));
        }
        CastSubcommand::CalldataEncode { sig, args } => {
            println!("{}", SimpleCast::calldata_encode(sig, &args)?);
        }
        CastSubcommand::PrettyCalldata { calldata, offline } => {
            let calldata = stdin::unwrap_line(calldata)?;
            println!("{}", pretty_calldata(&calldata, offline).await?);
        }
        CastSubcommand::Sig { sig, optimize } => {
            let sig = stdin::unwrap_line(sig)?;
            match optimize {
                Some(opt) => {
                    println!("Starting to optimize signature...");
                    let start_time = Instant::now();
                    let (selector, signature) = SimpleCast::get_selector(&sig, opt)?;
                    println!("Successfully generated in {:?}", start_time.elapsed());
                    println!("Selector: {selector}");
                    println!("Optimized signature: {signature}");
                }
                None => println!("{}", SimpleCast::get_selector(&sig, 0)?.0),
            }
        }

        // Blockchain & RPC queries
        CastSubcommand::Disassemble { bytecode } => {
            println!("{}", SimpleCast::disassemble(&bytecode)?);
        }
        CastSubcommand::Selectors { bytecode, resolve } => {
            let selectors_and_args = SimpleCast::extract_selectors(&bytecode)?;
            if resolve {
                let selectors_it = selectors_and_args.iter().map(|r| &r.0);
                let resolve_results =
                    decode_selectors(SelectorType::Function, selectors_it).await?;

                let max_args_len = selectors_and_args.iter().map(|r| r.1.len()).max().unwrap_or(0);
                for ((selector, arguments), func_names) in
                    selectors_and_args.into_iter().zip(resolve_results.into_iter())
                {
                    let resolved = match func_names {
                        Some(v) => v.join("|"),
                        None => "".to_string(),
                    };
                    println!("{selector}\t{arguments:max_args_len$}\t{resolved}");
                }
            } else {
                for (selector, arguments) in selectors_and_args {
                    println!("{selector}\t{arguments}");
                }
            }
        }
        CastSubcommand::Index { key_type, key, slot_number } => {
            println!("{}", SimpleCast::index(&key_type, &key, &slot_number)?);
        }
        // 4Byte
        CastSubcommand::FourByte { selector } => {
            let selector = stdin::unwrap_line(selector)?;
            let sigs = decode_function_selector(&selector).await?;
            if sigs.is_empty() {
                eyre::bail!("No matching function signatures found for selector `{selector}`");
            }
            for sig in sigs {
                println!("{sig}");
            }
        }
        CastSubcommand::FourByteDecode { calldata } => {
            let calldata = stdin::unwrap_line(calldata)?;
            let sigs = decode_calldata(&calldata).await?;
            sigs.iter().enumerate().for_each(|(i, sig)| println!("{}) \"{sig}\"", i + 1));

            let sig = match sigs.len() {
                0 => eyre::bail!("No signatures found"),
                1 => sigs.first().unwrap(),
                _ => {
                    let i: usize = prompt!("Select a function signature by number: ")?;
                    sigs.get(i - 1).ok_or_else(|| eyre::eyre!("Invalid signature index"))?
                }
            };

            let tokens = SimpleCast::calldata_decode(sig, &calldata, true)?;
            for token in format_tokens(&tokens) {
                println!("{token}");
            }
        }
        CastSubcommand::FourByteEvent { topic } => {
            let topic = stdin::unwrap_line(topic)?;
            let sigs = decode_event_topic(&topic).await?;
            if sigs.is_empty() {
                eyre::bail!("No matching event signatures found for topic `{topic}`");
            }
            for sig in sigs {
                println!("{sig}");
            }
        }

        // ENS
        CastSubcommand::Namehash { name } => {
            let name = stdin::unwrap_line(name)?;
            println!("{}", SimpleCast::namehash(&name)?);
        }

        // Misc
        CastSubcommand::Keccak { data } => {
            let bytes = match data {
                Some(data) => data.into_bytes(),
                None => stdin::read_bytes(false)?,
            };
            match String::from_utf8(bytes) {
                Ok(s) => {
                    let s = SimpleCast::keccak(&s)?;
                    println!("{s}");
                }
                Err(e) => {
                    let hash = keccak256(e.as_bytes());
                    let s = hex::encode(hash);
                    println!("0x{s}");
                }
            };
        }
        CastSubcommand::SigEvent { event_string } => {
            let event_string = stdin::unwrap_line(event_string)?;
            let parsed_event = get_event(&event_string)?;
            println!("{:?}", parsed_event.selector());
        }
        CastSubcommand::LeftShift { value, bits, base_in, base_out } => {
            println!("{}", SimpleCast::left_shift(&value, &bits, base_in.as_deref(), &base_out)?);
        }
        CastSubcommand::RightShift { value, bits, base_in, base_out } => {
            println!("{}", SimpleCast::right_shift(&value, &bits, base_in.as_deref(), &base_out)?);
        }
        CastSubcommand::Create2(cmd) => {
            cmd.run()?;
        }
    };
    Ok(())
}
