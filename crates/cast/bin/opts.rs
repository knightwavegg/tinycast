use crate::cmd::create2::Create2Args;
use alloy_primitives::{Address, B256, U256};
use clap::{Parser, Subcommand};
use eyre::Result;
use std::str::FromStr;

const VERSION_MESSAGE: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("VERGEN_GIT_SHA"),
    " ",
    env!("VERGEN_BUILD_TIMESTAMP"),
    ")"
);

/// Perform Ethereum RPC calls from the comfort of your command line.
#[derive(Parser)]
#[command(
    name = "cast",
    version = VERSION_MESSAGE,
    after_help = "Find more information in the book: http://book.getfoundry.sh/reference/cast/cast.html",
    next_display_order = None,
)]
pub struct Cast {
    #[command(subcommand)]
    pub cmd: CastSubcommand,
}

#[derive(Subcommand)]
pub enum CastSubcommand {
    /// Prints the maximum value of the given integer type.
    #[command(visible_aliases = &["--max-int", "maxi"])]
    MaxInt {
        /// The integer type to get the maximum value of.
        #[arg(default_value = "int256")]
        r#type: String,
    },

    /// Prints the minimum value of the given integer type.
    #[command(visible_aliases = &["--min-int", "mini"])]
    MinInt {
        /// The integer type to get the minimum value of.
        #[arg(default_value = "int256")]
        r#type: String,
    },

    /// Prints the maximum value of the given integer type.
    #[command(visible_aliases = &["--max-uint", "maxu"])]
    MaxUint {
        /// The unsigned integer type to get the maximum value of.
        #[arg(default_value = "uint256")]
        r#type: String,
    },

    /// Prints the zero address.
    #[command(visible_aliases = &["--address-zero", "az"])]
    AddressZero,

    /// Prints the zero hash.
    #[command(visible_aliases = &["--hash-zero", "hz"])]
    HashZero,

    /// Convert UTF8 text to hex.
    #[command(
        visible_aliases = &[
        "--from-ascii",
        "--from-utf8",
        "from-ascii",
        "fu",
        "fa"]
    )]
    FromUtf8 {
        /// The text to convert.
        text: Option<String>,
    },

    /// Concatenate hex strings.
    #[command(visible_aliases = &["--concat-hex", "ch"])]
    ConcatHex {
        /// The data to concatenate.
        data: Vec<String>,
    },

    /// Convert binary data into hex data.
    #[command(visible_aliases = &["--from-bin", "from-binx", "fb"])]
    FromBin,

    /// Normalize the input to lowercase, 0x-prefixed hex.
    ///
    /// The input can be:
    /// - mixed case hex with or without 0x prefix
    /// - 0x prefixed hex, concatenated with a ':'
    /// - an absolute path to file
    /// - @tag, where the tag is defined in an environment variable
    #[command(visible_aliases = &["--to-hexdata", "thd", "2hd"])]
    ToHexdata {
        /// The input to normalize.
        input: Option<String>,
    },

    /// Convert an address to a checksummed format (EIP-55).
    #[command(
        visible_aliases = &["--to-checksum-address",
        "--to-checksum",
        "to-checksum",
        "ta",
        "2a"]
    )]
    ToCheckSumAddress {
        /// The address to convert.
        address: Option<Address>,
    },

    /// Convert hex data to an ASCII string.
    #[command(visible_aliases = &["--to-ascii", "tas", "2as"])]
    ToAscii {
        /// The hex data to convert.
        hexdata: Option<String>,
    },

    /// Convert a fixed point number into an integer.
    #[command(visible_aliases = &["--from-fix", "ff"])]
    FromFixedPoint {
        /// The number of decimals to use.
        decimals: Option<String>,

        /// The value to convert.
        #[arg(allow_hyphen_values = true)]
        value: Option<String>,
    },

    /// Right-pads hex data to 32 bytes.
    #[command(visible_aliases = &["--to-bytes32", "tb", "2b"])]
    ToBytes32 {
        /// The hex data to convert.
        bytes: Option<String>,
    },

    /// Convert an integer into a fixed point number.
    #[command(visible_aliases = &["--to-fix", "tf", "2f"])]
    ToFixedPoint {
        /// The number of decimals to use.
        decimals: Option<String>,

        /// The value to convert.
        #[arg(allow_hyphen_values = true)]
        value: Option<String>,
    },

    /// Convert a number to a hex-encoded uint256.
    #[command(name = "to-uint256", visible_aliases = &["--to-uint256", "tu", "2u"])]
    ToUint256 {
        /// The value to convert.
        value: Option<String>,
    },

    /// Convert a number to a hex-encoded int256.
    #[command(name = "to-int256", visible_aliases = &["--to-int256", "ti", "2i"])]
    ToInt256 {
        /// The value to convert.
        value: Option<String>,
    },

    /// Perform a left shifting operation
    #[command(name = "shl")]
    LeftShift {
        /// The value to shift.
        value: String,

        /// The number of bits to shift.
        bits: String,

        /// The input base.
        #[arg(long)]
        base_in: Option<String>,

        /// The output base.
        #[arg(long, default_value = "16")]
        base_out: String,
    },

    /// Perform a right shifting operation
    #[command(name = "shr")]
    RightShift {
        /// The value to shift.
        value: String,

        /// The number of bits to shift.
        bits: String,

        /// The input base,
        #[arg(long)]
        base_in: Option<String>,

        /// The output base,
        #[arg(long, default_value = "16")]
        base_out: String,
    },

    /// Convert an ETH amount into another unit (ether, gwei or wei).
    ///
    /// Examples:
    /// - 1ether wei
    /// - "1 ether" wei
    /// - 1ether
    /// - 1 gwei
    /// - 1gwei ether
    #[command(visible_aliases = &["--to-unit", "tun", "2un"])]
    ToUnit {
        /// The value to convert.
        value: Option<String>,

        /// The unit to convert to (ether, gwei, wei).
        #[arg(default_value = "wei")]
        unit: String,
    },

    /// Convert an ETH amount to wei.
    ///
    /// Consider using --to-unit.
    #[command(visible_aliases = &["--to-wei", "tw", "2w"])]
    ToWei {
        /// The value to convert.
        #[arg(allow_hyphen_values = true)]
        value: Option<String>,

        /// The unit to convert from (ether, gwei, wei).
        #[arg(default_value = "eth")]
        unit: String,
    },

    /// Convert wei into an ETH amount.
    ///
    /// Consider using --to-unit.
    #[command(visible_aliases = &["--from-wei", "fw"])]
    FromWei {
        /// The value to convert.
        #[arg(allow_hyphen_values = true)]
        value: Option<String>,

        /// The unit to convert from (ether, gwei, wei).
        #[arg(default_value = "eth")]
        unit: String,
    },

    /// RLP encodes hex data, or an array of hex data.
    #[command(visible_aliases = &["--to-rlp"])]
    ToRlp {
        /// The value to convert.
        value: Option<String>,
    },

    /// Decodes RLP encoded data.
    ///
    /// Input must be hexadecimal.
    #[command(visible_aliases = &["--from-rlp"])]
    FromRlp {
        /// The value to convert.
        value: Option<String>,
    },

    /// Converts a number of one base to another
    #[command(visible_aliases = &["--to-hex", "th", "2h"])]
    ToHex(ToBaseArgs),

    /// Converts a number of one base to decimal
    #[command(visible_aliases = &["--to-dec", "td", "2d"])]
    ToDec(ToBaseArgs),

    /// Converts a number of one base to another
    #[command(
        visible_aliases = &["--to-base",
        "--to-radix",
        "to-radix",
        "tr",
        "2r"]
    )]
    ToBase {
        #[command(flatten)]
        base: ToBaseArgs,

        /// The output base.
        #[arg(value_name = "BASE")]
        base_out: Option<String>,
    },

    /// ABI-encode a function with arguments.
    #[command(name = "calldata", visible_alias = "cd")]
    CalldataEncode {
        /// The function signature in the format `<name>(<in-types>)(<out-types>)`
        sig: String,

        /// The arguments to encode.
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },


    /// Disassembles hex encoded bytecode into individual / human readable opcodes
    #[command(visible_alias = "da")]
    Disassemble {
        /// The hex encoded bytecode.
        bytecode: String,
    },

    /// Calculate the ENS namehash of a name.
    #[command(visible_aliases = &["na", "nh"])]
    Namehash { name: Option<String> },

    /// Decode ABI-encoded input data.
    ///
    /// Similar to `abi-decode --input`, but function selector MUST be prefixed in `calldata`
    /// string
    #[command(visible_aliases = &["--calldata-decode","cdd"])]
    CalldataDecode {
        /// The function signature in the format `<name>(<in-types>)(<out-types>)`.
        sig: String,

        /// The ABI-encoded calldata.
        calldata: String,
    },

    /// Decode ABI-encoded input or output data.
    ///
    /// Defaults to decoding output data. To decode input data pass --input.
    ///
    /// When passing `--input`, function selector must NOT be prefixed in `calldata` string
    #[command(name = "abi-decode", visible_aliases = &["ad", "--abi-decode"])]
    AbiDecode {
        /// The function signature in the format `<name>(<in-types>)(<out-types>)`.
        sig: String,

        /// The ABI-encoded calldata.
        calldata: String,

        /// Whether to decode the input or output data.
        #[arg(long, short, help_heading = "Decode input data instead of output data")]
        input: bool,
    },

    /// ABI encode the given function argument, excluding the selector.
    #[command(visible_alias = "ae")]
    AbiEncode {
        /// The function signature.
        sig: String,

        /// Whether to use packed encoding.
        #[arg(long)]
        packed: bool,

        /// The arguments of the function.
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Compute the storage slot for an entry in a mapping.
    #[command(visible_alias = "in")]
    Index {
        /// The mapping key type.
        key_type: String,

        /// The mapping key.
        key: String,

        /// The storage slot of the mapping.
        slot_number: String,
    },

    /// Get the function signatures for the given selector from https://openchain.xyz.
    #[command(name = "4byte", visible_aliases = &["4", "4b"])]
    FourByte {
        /// The function selector.
        selector: Option<String>,
    },

    /// Decode ABI-encoded calldata using https://openchain.xyz.
    #[command(name = "4byte-decode", visible_aliases = &["4d", "4bd"])]
    FourByteDecode {
        /// The ABI-encoded calldata.
        calldata: Option<String>,
    },

    /// Get the event signature for a given topic 0 from https://openchain.xyz.
    #[command(name = "4byte-event", visible_aliases = &["4e", "4be", "topic0-event", "t0e"])]
    FourByteEvent {
        /// Topic 0
        #[arg(value_name = "TOPIC_0")]
        topic: Option<String>,
    },

    /// Pretty print calldata.
    ///
    /// Tries to decode the calldata using https://openchain.xyz unless --offline is passed.
    #[command(visible_alias = "pc")]
    PrettyCalldata {
        /// The calldata.
        calldata: Option<String>,

        /// Skip the https://openchain.xyz lookup.
        #[arg(long, short)]
        offline: bool,
    },

    /// Generate event signatures from event string.
    #[command(visible_alias = "se")]
    SigEvent {
        /// The event string.
        event_string: Option<String>,
    },

    /// Hash arbitrary data using Keccak-256.
    #[command(visible_alias = "k")]
    Keccak {
        /// The data to hash.
        data: Option<String>,
    },

    /// Get the selector for a function.
    #[command(visible_alias = "si")]
    Sig {
        /// The function signature, e.g. transfer(address,uint256).
        sig: Option<String>,

        /// Optimize signature to contain provided amount of leading zeroes in selector.
        optimize: Option<usize>,
    },

    /// Generate a deterministic contract address using CREATE2.
    #[command(visible_alias = "c2")]
    Create2(Create2Args),

    /// Formats a string into bytes32 encoding.
    #[command(name = "format-bytes32-string", visible_aliases = &["--format-bytes32-string"])]
    FormatBytes32String {
        /// The string to format.
        string: Option<String>,
    },

    /// Parses a string from bytes32 encoding.
    #[command(name = "parse-bytes32-string", visible_aliases = &["--parse-bytes32-string"])]
    ParseBytes32String {
        /// The string to parse.
        bytes: Option<String>,
    },
    #[command(name = "parse-bytes32-address", visible_aliases = &["--parse-bytes32-address"])]
    #[command(about = "Parses a checksummed address from bytes32 encoding.")]
    ParseBytes32Address {
        #[arg(value_name = "BYTES")]
        bytes: Option<String>,
    },

    /// Extracts function selectors and arguments from bytecode
    #[command(visible_alias = "sel")]
    Selectors {
        /// The hex encoded bytecode.
        bytecode: String,

        /// Resolve the function signatures for the extracted selectors using https://openchain.xyz
        #[arg(long, short)]
        resolve: bool,
    },
}

/// CLI arguments for `cast --to-base`.
#[derive(Debug, Parser)]
pub struct ToBaseArgs {
    /// The value to convert.
    #[arg(allow_hyphen_values = true)]
    pub value: Option<String>,

    /// The input base.
    #[arg(long, short = 'i')]
    pub base_in: Option<String>,
}

pub fn parse_slot(s: &str) -> Result<B256> {
    let slot = U256::from_str(s).map_err(|e| eyre::eyre!("Could not parse slot number: {e}"))?;
    Ok(B256::from(slot))
}
