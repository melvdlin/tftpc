//! # a (Tremendously) Trivial File Transfer Protocol implementation
//!
//! A sans-io, no-std, no-alloc TFTP implementation
//! as according to [RFC 1350](https://datatracker.ietf.org/doc/html/rfc1350).
//!
//! Currently, this crate implements only a client and does not support options.

#![no_std]
#![allow(clippy::let_and_return)]
#![forbid(unused_must_use)]
#![forbid(unsafe_code)]

pub mod client;

use core::error::Error;
use core::ffi::CStr;
use core::fmt::{Debug, Display};

type IntoIter<T> = <T as IntoIterator>::IntoIter;

/// The (maximum) size of a TFTP packet.
pub const PACKET_SIZE: usize = HEADER_SIZE + BLOCK_SIZE;

const HEADER_SIZE: usize = OPCODE_SIZE + BLOCK_NO_SIZE;
const OPCODE_SIZE: usize = size_of::<u16>();
const BLOCK_NO_SIZE: usize = size_of::<u16>();

/// The size of a payload data block.
pub const BLOCK_SIZE: usize = 512;

macro_rules! concat_arrays {
    ($default:expr, $t:ty; $($a:expr),* $(,)?) => {
        {
            const TOTAL_LEN: usize = 0 $(+ $a.len())*;
            let mut arr = [$default; TOTAL_LEN];
            let mut i = 0;
            while i < TOTAL_LEN {
                let mut relative_i = i;
                $(
                    if relative_i < $a.len() {
                        arr[i] = $a[relative_i];
                        i += 1;
                        continue;
                    } else {
                        relative_i -= $a.len();
                    }
                )*
                let _ = relative_i;
                panic!("index out of range!");
            }
            arr
        }
    };
}

macro_rules! infer_array_size {
    ($(#[$attrs:meta])* $vis:vis $bind:ident $ident:ident: [$t:ty; _] = $val:expr $(;)?) => {
        $(#[$attrs])*
        $vis $bind $ident: [$t; $val.len()] = $val;
    };
}

infer_array_size! {
    /// The response to a packet with an unknown transfer ID.
    ///
    /// As with any error packet, sending this is pure courtesy.
    pub const UNKNOWN_TID_PACKET: [u8; _] = concat_arrays! {
        0, u8;
        (Opcode::Error as u16).to_be_bytes(),
        (ErrorCode::UnknownTransferID as u16).to_be_bytes(),
        b"\0",
    };
}

/// A TFTP error code.
#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
#[derive(PartialOrd, Ord)]
#[derive(Hash)]
pub enum ErrorCode {
    Undefined = 0,
    FileNotFound = 1,
    AccessViolation = 2,
    DiskFull = 3,
    IllegalOperation = 4,
    UnknownTransferID = 5,
    FileAlreadyExists = 6,
    NoSuchUser = 7,
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                | ErrorCode::Undefined => "Not defined, see error message (if any).",
                | ErrorCode::FileNotFound => "File not found.",
                | ErrorCode::AccessViolation => "Access violation.",
                | ErrorCode::DiskFull => "Disk full or allocation exceeded.",
                | ErrorCode::IllegalOperation => "Illegal TFTP operation.",
                | ErrorCode::UnknownTransferID => "Unknown transfer ID.",
                | ErrorCode::FileAlreadyExists => "File already exists.",
                | ErrorCode::NoSuchUser => "No such user.",
            }
        )
    }
}

impl TryFrom<u16> for ErrorCode {
    type Error = UnknownErrorCode;

    fn try_from(code: u16) -> Result<Self, Self::Error> {
        [
            ErrorCode::Undefined,
            ErrorCode::FileNotFound,
            ErrorCode::AccessViolation,
            ErrorCode::DiskFull,
            ErrorCode::IllegalOperation,
            ErrorCode::UnknownTransferID,
            ErrorCode::FileAlreadyExists,
            ErrorCode::NoSuchUser,
        ]
        .into_iter()
        .find(|error_code| code == *error_code as u16)
        .ok_or(UnknownErrorCode(code))
    }
}

/// An [`Error`] that can occur when creating an [`ErrorCode`] from a [`u16`].
#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub struct UnknownErrorCode(
    /// The unknown error code.
    pub u16,
);

impl Error for UnknownErrorCode {}

impl Display for UnknownErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "unknown error code ({})", self.0)
    }
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
enum Packet<'buf> {
    Rrq(Rwrq<'buf>),
    Wrq(Rwrq<'buf>),
    Data(Data<'buf>),
    Ack(Ack),
    Error(ProtocolError<'buf>),
}

impl<'buf> Packet<'buf> {
    pub const fn opcode(&self) -> Opcode {
        match self {
            | Packet::Rrq(_) => Opcode::Rrq,
            | Packet::Wrq(_) => Opcode::Wrq,
            | Packet::Data(_) => Opcode::Data,
            | Packet::Ack(_) => Opcode::Ack,
            | Packet::Error(_) => Opcode::Error,
        }
    }
}

impl<'buf> From<Data<'buf>> for Packet<'buf> {
    fn from(data: Data<'buf>) -> Self {
        Packet::Data(data)
    }
}

impl<'buf> From<Ack> for Packet<'buf> {
    fn from(ack: Ack) -> Self {
        Packet::Ack(ack)
    }
}

impl<'buf> From<ProtocolError<'buf>> for Packet<'buf> {
    fn from(error: ProtocolError<'buf>) -> Self {
        Packet::Error(error)
    }
}

impl<'buf> Packet<'buf> {
    pub fn bytes(&self) -> Result<PacketBytes, TooLongError> {
        PacketBytes::new(self)
    }
}

#[derive(Debug)]
#[derive(Clone)]
struct PacketBytes<'payload> {
    opcode: OpcodeBytes,
    payload: PayloadBytes<'payload>,
}

impl<'payload> PacketBytes<'payload> {
    /// Returns an error iff the packet would yield more than `usize::MAX` bytes
    pub fn new(packet: &'payload Packet) -> Result<Self, TooLongError> {
        let opcode = OpcodeBytes::new(packet.opcode());
        let payload = PayloadBytes::new(packet)?;
        if opcode.len().checked_add(payload.len()).is_none() {
            return Err(TooLongError {
                actual_len: None,
                max_len: usize::MAX,
            });
        }
        Ok(PacketBytes { opcode, payload })
    }
}

impl<'payload> Iterator for PacketBytes<'payload> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.opcode.next().or_else(|| self.payload.next())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl<'a> ExactSizeIterator for PacketBytes<'a> {
    fn len(&self) -> usize {
        self.opcode.len() + self.payload.len()
    }
}

#[derive(Debug)]
#[derive(Clone)]
struct OpcodeBytes {
    inner: IntoIter<[u8; 2]>,
}

impl OpcodeBytes {
    pub fn new(opcode: Opcode) -> Self {
        Self {
            inner: (opcode as u16).to_be_bytes().into_iter(),
        }
    }
}

impl Iterator for OpcodeBytes {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for OpcodeBytes {
    fn len(&self) -> usize {
        self.inner.len()
    }
}

#[derive(Debug)]
#[derive(Clone)]
enum PayloadBytes<'a> {
    Rwrq(RwrqBytes<'a>),
    Data(DataBytes<'a>),
    Ack(AckBytes),
    Error(ErrorBytes<'a>),
}

impl<'a> PayloadBytes<'a> {
    pub fn new(packet: &'a Packet) -> Result<Self, TooLongError> {
        Ok(match packet {
            | Packet::Rrq(rwrq) | Packet::Wrq(rwrq) => Self::Rwrq(RwrqBytes::new(rwrq)?),
            | Packet::Data(data) => Self::Data(DataBytes::new(data)?),
            | Packet::Ack(ack) => Self::Ack(AckBytes::new(ack)),
            | Packet::Error(error) => Self::Error(ErrorBytes::new(error)?),
        })
    }
}

impl<'a> Iterator for PayloadBytes<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            | PayloadBytes::Rwrq(rwrq_bytes) => rwrq_bytes.next(),
            | PayloadBytes::Data(data_bytes) => data_bytes.next(),
            | PayloadBytes::Ack(ack_bytes) => ack_bytes.next(),
            | PayloadBytes::Error(error_bytes) => error_bytes.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl<'a> ExactSizeIterator for PayloadBytes<'a> {
    fn len(&self) -> usize {
        match self {
            | PayloadBytes::Rwrq(inner) => inner.len(),
            | PayloadBytes::Data(inner) => inner.len(),
            | PayloadBytes::Ack(inner) => inner.len(),
            | PayloadBytes::Error(inner) => inner.len(),
        }
    }
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
struct Rwrq<'a> {
    filename: &'a CStr,
    mode: &'a CStr,
}

#[derive(Debug)]
#[derive(Clone)]
struct RwrqBytes<'a> {
    filename: CStrBytes<'a>,
    mode: CStrBytes<'a>,
}

impl<'a> RwrqBytes<'a> {
    /// Returns an error iff the RWRQ payload would yield more than `usize::MAX` bytes
    pub fn new(rwrq: &'a Rwrq) -> Result<Self, TooLongError> {
        let filename = CStrBytes::from_cstr(rwrq.filename);
        let mode = CStrBytes::from_cstr(rwrq.mode);

        if filename.len().checked_add(mode.len()).is_none() {
            return Err(TooLongError {
                actual_len: None,
                max_len: usize::MAX,
            });
        }

        Ok(Self { filename, mode })
    }

    /// Includes nul terminator.
    pub fn filename(&mut self) -> &mut (impl ExactSizeIterator<Item = u8> + Clone + 'a) {
        &mut self.filename
    }

    /// Includes nul terminator.
    pub fn mode(&mut self) -> &mut (impl ExactSizeIterator<Item = u8> + Clone + 'a) {
        &mut self.mode
    }
}

impl<'a> Iterator for RwrqBytes<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.filename.next().or_else(|| self.mode.next())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl<'a> ExactSizeIterator for RwrqBytes<'a> {
    fn len(&self) -> usize {
        self.filename.len() + self.mode.len()
    }
}

/// Includes nul terminator.
#[derive(Debug)]
#[derive(Clone)]
struct CStrBytes<'cstr> {
    inner: core::iter::Copied<IntoIter<&'cstr [u8]>>,
}

impl<'str> CStrBytes<'str> {
    pub fn from_cstr(cstr: &'str CStr) -> Self {
        Self {
            inner: cstr.to_bytes_with_nul().iter().copied(),
        }
    }
}

impl<'str> Iterator for CStrBytes<'str> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<'cstr> ExactSizeIterator for CStrBytes<'cstr> {}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
struct Data<'a> {
    block_no: u16,
    data: &'a [u8],
}

#[derive(Debug)]
#[derive(Clone)]
struct DataBytes<'a> {
    block_no: IntoIter<[u8; 2]>,
    data: core::iter::Copied<IntoIter<&'a [u8]>>,
}

impl<'a> DataBytes<'a> {
    /// Returns an error iff the data payload would yield more than `usize::MAX` bytes
    pub fn new(data: &'a Data) -> Result<Self, TooLongError> {
        let block_no = data.block_no.to_be_bytes().into_iter();
        let data = data.data.iter().copied();

        if block_no.len().checked_add(data.len()).is_none() {
            return Err(TooLongError {
                actual_len: None,
                max_len: usize::MAX,
            });
        }

        Ok(DataBytes { block_no, data })
    }

    #[allow(dead_code)]
    pub fn block_no(&mut self) -> &mut impl ExactSizeIterator<Item = u8> {
        &mut self.block_no
    }

    #[allow(dead_code)]
    pub fn data(&mut self) -> &mut (impl ExactSizeIterator<Item = u8> + 'a) {
        &mut self.data
    }
}

impl<'a> Iterator for DataBytes<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.block_no.next().or_else(|| self.data.next())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl<'a> ExactSizeIterator for DataBytes<'a> {
    fn len(&self) -> usize {
        self.block_no.len() + self.data.len()
    }
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
struct Ack {
    block_no: u16,
}

#[derive(Debug)]
#[derive(Clone)]
struct AckBytes {
    block_no: IntoIter<[u8; 2]>,
}

impl AckBytes {
    pub fn new(ack: &Ack) -> Self {
        Self {
            block_no: ack.block_no.to_be_bytes().into_iter(),
        }
    }

    #[allow(dead_code)]
    pub fn block_no(&mut self) -> &mut impl ExactSizeIterator<Item = u8> {
        &mut self.block_no
    }
}

impl Iterator for AckBytes {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.block_no.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for AckBytes {
    fn len(&self) -> usize {
        self.block_no.len()
    }
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
struct ProtocolError<'a> {
    code: ErrorCode,
    message: &'a CStr,
}

#[derive(Debug)]
#[derive(Clone)]
struct ErrorBytes<'message> {
    error_code: IntoIter<[u8; 2]>,
    message: CStrBytes<'message>,
}

impl<'message> ErrorBytes<'message> {
    /// Returns an error iff the error payload would yield more than `usize::MAX` bytes
    pub fn new(error: &'message ProtocolError) -> Result<Self, TooLongError> {
        let error_code = (error.code as u16).to_be_bytes().into_iter();
        let message = CStrBytes::from_cstr(error.message);

        if error_code.len().checked_add(message.len()).is_none() {
            return Err(TooLongError {
                actual_len: None,
                max_len: usize::MAX,
            });
        }

        Ok(Self {
            error_code,
            message,
        })
    }

    #[allow(dead_code)]
    pub fn error_code(&mut self) -> &mut impl ExactSizeIterator<Item = u8> {
        &mut self.error_code
    }

    #[allow(dead_code)]
    pub fn message(&mut self) -> &mut (impl ExactSizeIterator<Item = u8> + 'message) {
        &mut self.message
    }
}

impl<'a> Iterator for ErrorBytes<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.error_code.next().or_else(|| self.message.next())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl<'a> ExactSizeIterator for ErrorBytes<'a> {
    fn len(&self) -> usize {
        self.error_code.len() + self.message.len()
    }
}

/// An [`Error`] indicating that a sequence of data exceeds some maximum length.
#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub struct TooLongError {
    pub actual_len: Option<usize>,
    pub max_len: usize,
}

impl Display for TooLongError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(actual) = self.actual_len {
            write!(
                f,
                "sequence is too long (maximum len: {}; actual len: {})",
                self.max_len, actual
            )
        } else {
            write!(
                f,
                "sequence is too long (maximum len: {}; actual len > `usize::MAX`)",
                self.max_len
            )
        }
    }
}

impl Error for TooLongError {}
#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]

enum Opcode {
    Rrq = 1,
    Wrq = 2,
    Data = 3,
    Ack = 4,
    Error = 5,
}

impl TryFrom<u16> for Opcode {
    type Error = UnknownOpcode;

    fn try_from(code: u16) -> Result<Self, UnknownOpcode> {
        [
            Opcode::Rrq,
            Opcode::Wrq,
            Opcode::Data,
            Opcode::Ack,
            Opcode::Error,
        ]
        .into_iter()
        .find(|opcode| code == *opcode as u16)
        .ok_or(UnknownOpcode(code))
    }
}

/// An [`Error`] that can occur when creating an [`OpCode`] from a [`u16`].
#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
struct UnknownOpcode(pub u16);

impl Error for UnknownOpcode {}

impl Display for UnknownOpcode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "unknown opcode ({})", self.0)
    }
}

/// The file transfer mode.
#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
#[non_exhaustive]
pub enum Mode {
    Netascii,
    Octect,
}

impl Mode {
    pub const fn as_str(self) -> &'static str {
        match self {
            | Mode::Netascii => "netascii",
            | Mode::Octect => "octet",
        }
    }

    pub const fn as_cstr(self) -> &'static CStr {
        match self {
            | Mode::Netascii => c"netascii",
            | Mode::Octect => c"octet",
        }
    }
}

impl<'cstr> TryFrom<&'cstr CStr> for Mode {
    type Error = UnknownMode<'cstr>;

    fn try_from(cstr: &'cstr CStr) -> Result<Self, Self::Error> {
        let bytes = cstr.to_bytes();
        for mode in [Self::Netascii, Self::Octect] {
            if bytes.eq_ignore_ascii_case(mode.as_cstr().to_bytes()) {
                return Ok(mode);
            }
        }
        Err(UnknownMode(cstr))
    }
}

/// An [`Error`] that can occur when parsing a [`Mode`] from a [`CStr`].
#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub struct UnknownMode<'a>(
    /// The unknown mode string.
    pub &'a CStr,
);

impl<'a> Error for UnknownMode<'a> {}

impl<'a> Display for UnknownMode<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "unknown mode '{}'", self.0.display())
    }
}

mod parser {

    use super::*;
    use nom::branch::*;
    use nom::bytes::streaming::*;
    use nom::combinator::*;
    use nom::number::streaming::be_u16;
    use nom::sequence::*;
    use nom::IResult;
    use nom::Parser;

    pub fn packet<'a>() -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Packet<'a>> {
        let rrq = rrq_packet().map(Packet::Rrq);
        let wrq = wrq_packet().map(Packet::Wrq);
        let data = data_packet().map(Packet::Data);
        let ack = ack_packet().map(Packet::Ack);
        let error = error_packet().map(Packet::Error);

        alt((rrq, wrq, data, ack, error))
    }

    pub fn rrq_packet<'input>(
    ) -> impl Parser<&'input [u8], Rwrq<'input>, nom::error::Error<&'input [u8]>> {
        preceded(opcode(Opcode::Rrq), rwrq())
    }

    pub fn wrq_packet<'input>(
    ) -> impl Parser<&'input [u8], Rwrq<'input>, nom::error::Error<&'input [u8]>> {
        preceded(opcode(Opcode::Wrq), rwrq())
    }

    pub fn data_packet<'input>(
    ) -> impl Parser<&'input [u8], Data<'input>, nom::error::Error<&'input [u8]>> {
        preceded(opcode(Opcode::Data), data())
    }

    pub fn ack_packet<'input>(
    ) -> impl Parser<&'input [u8], Ack, nom::error::Error<&'input [u8]>> {
        preceded(opcode(Opcode::Ack), ack())
    }

    pub fn error_packet<'input>(
    ) -> impl Parser<&'input [u8], ProtocolError<'input>, nom::error::Error<&'input [u8]>>
    {
        preceded(opcode(Opcode::Error), error())
    }

    pub fn rwrq<'input>(
    ) -> impl Parser<&'input [u8], Rwrq<'input>, nom::error::Error<&'input [u8]>> {
        tuple((cstr(), cstr())).map(|(filename, mode)| Rwrq { filename, mode })
    }

    pub fn data<'input>(
    ) -> impl Parser<&'input [u8], Data<'input>, nom::error::Error<&'input [u8]>> {
        tuple((be_u16, rest)).map(|(block_no, data)| Data { block_no, data })
    }

    pub fn ack<'input>() -> impl Parser<&'input [u8], Ack, nom::error::Error<&'input [u8]>>
    {
        be_u16.map(|block_no| Ack { block_no })
    }

    pub fn error<'input>(
    ) -> impl Parser<&'input [u8], ProtocolError<'input>, nom::error::Error<&'input [u8]>>
    {
        map_res(tuple((be_u16, cstr())), |(error_code, message)| {
            Ok::<_, UnknownErrorCode>(ProtocolError {
                code: ErrorCode::try_from(error_code)?,
                message,
            })
        })
    }

    fn opcode<'input>(
        opcode: Opcode,
    ) -> impl Parser<&'input [u8], Opcode, nom::error::Error<&'input [u8]>> {
        value(opcode, tag((opcode as u16).to_be_bytes()))
    }

    // adapted from nom::streaming::take_until
    fn cstr() -> impl for<'input> Fn(
        &'input [u8],
    ) -> IResult<
        &'input [u8],
        &'input CStr,
        nom::error::Error<&'input [u8]>,
    > {
        use nom::FindSubstring;

        fn f(i: &[u8]) -> IResult<&[u8], &CStr, nom::error::Error<&[u8]>> {
            let Some(nul_pos) = i.find_substring(b"\0".as_slice()) else {
                return Err(nom::Err::Incomplete(nom::Needed::Unknown));
            };

            let (cstr, rest) = i.split_at(nul_pos + 1);
            let cstr = CStr::from_bytes_with_nul(cstr)
                .expect("only nul byte should be at index + 1");
            Ok((rest, cstr))
        }

        f
    }

    #[allow(dead_code)]
    pub fn mode<'input>(
        mode: Mode,
    ) -> impl Parser<&'input [u8], Mode, nom::error::Error<&'input [u8]>> {
        value(mode, tag_no_case(mode.as_cstr().to_bytes_with_nul()))
    }

    #[allow(dead_code)]
    pub fn parse_mode<'input>(
    ) -> impl Parser<&'input [u8], Mode, nom::error::Error<&'input [u8]>> {
        let netascii = mode(Mode::Netascii);
        let octet = mode(Mode::Octect);

        alt((netascii, octet))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        const LOREM: &str = include_str!("lorem.txt");

        #[test]
        fn test_packet() {
            let mut buf = [0u8; PACKET_SIZE];

            {
                let rrq = Packet::Rrq(Rwrq {
                    filename: c"foobar.txt",
                    mode: c"octet",
                });

                let mut rrq_bytes = rrq.bytes().unwrap();
                let rrq_len = rrq_bytes.len();
                buf.fill_with(|| rrq_bytes.next().unwrap_or(0));

                assert_eq!(packet().parse(&buf), Ok((&buf[rrq_len..], rrq)));
                assert!(matches!(
                    packet().parse(&buf[..rrq_len - 1]),
                    Err(nom::Err::Incomplete(_))
                ));
            }

            {
                let wrq = Packet::Rrq(Rwrq {
                    filename: c"foobar.txt",
                    mode: c"octet",
                });

                let mut wrq_bytes = wrq.bytes().unwrap();
                let wrq_len = wrq_bytes.len();
                buf.fill_with(|| wrq_bytes.next().unwrap_or(0));

                assert_eq!(packet().parse(&buf), Ok((&buf[wrq_len..], wrq)));
                assert!(matches!(
                    packet().parse(&buf[..wrq_len - 1]),
                    Err(nom::Err::Incomplete(_))
                ))
            }

            {
                let data = Packet::Data(Data {
                    block_no: 54321,
                    data: &LOREM.as_bytes()[..BLOCK_SIZE],
                });

                let mut data_bytes = data.bytes().unwrap();
                let data_len = data_bytes.len();
                buf.fill_with(|| data_bytes.next().unwrap_or(0));

                assert_eq!(packet().parse(&buf), Ok((&buf[data_len..], data)));
                assert!(packet().parse(&buf[..data_len - 1]).is_ok())
            }

            {
                let ack = Packet::Ack(Ack { block_no: 12345 });

                let mut ack_bytes = ack.bytes().unwrap();
                let ack_len = ack_bytes.len();
                buf.fill_with(|| ack_bytes.next().unwrap_or(0));

                assert_eq!(packet().parse(&buf), Ok((&buf[ack_len..], ack)));
                assert!(matches!(
                    packet().parse(&buf[..ack_len - 1]),
                    Err(nom::Err::Incomplete(_))
                ))
            }

            {
                let error = Packet::Error(ProtocolError {
                    code: ErrorCode::FileNotFound,
                    message: c"foobar",
                });

                let mut error_bytes = error.bytes().unwrap();
                let error_len = error_bytes.len();
                buf.fill_with(|| error_bytes.next().unwrap_or(0));

                assert_eq!(packet().parse(&buf), Ok((&buf[error_len..], error)));
                assert!(matches!(
                    packet().parse(&buf[..error_len - 1]),
                    Err(nom::Err::Incomplete(_))
                ));
            }
        }

        #[test]
        fn test_bad_opcode() {
            let mut buf = [0_u8; PACKET_SIZE];

            let rrq = Packet::Rrq(Rwrq {
                filename: c"foobar.txt",
                mode: c"octet",
            });

            let mut rrq_bytes = rrq.bytes().unwrap();
            buf.fill_with(|| rrq_bytes.next().unwrap_or(0));
            *<&mut [u8; 2]>::try_from(&mut buf[..2]).unwrap() = 0x34_u16.to_be_bytes();

            assert!(matches!(packet().parse(&buf), Err(nom::Err::Error(_))));
        }
    }
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
#[derive(PartialOrd, Ord)]
struct DisplayCStr<'cstr>(pub &'cstr CStr);

impl<'cstr> Display for DisplayCStr<'cstr> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for c in self.0.to_bytes_with_nul().iter().copied().map(char::from) {
            write!(f, "{}", c)?;
        }
        Ok(())
    }
}

trait DisplayExt {
    fn display(&self) -> impl Display;
}

impl DisplayExt for CStr {
    fn display(&self) -> impl Display {
        DisplayCStr(self)
    }
}

/// Like [`core::iter::zip`], but only works with [`core::iter::ExactSizeIterator`]
/// as underlying iterators.
/// This requirement exists so that [`PureZip`]
/// can advance the underlying iterators only when both will yield an item.
fn pure_zip<A, B>(left: A, right: B) -> PureZip<A::IntoIter, B::IntoIter>
where
    A: IntoIterator<IntoIter: ExactSizeIterator>,
    B: IntoIterator<IntoIter: ExactSizeIterator>,
{
    PureZip {
        left: left.into_iter(),
        right: right.into_iter(),
    }
}

/// See [`pure_zip`].
#[derive(Debug)]
struct PureZip<A, B> {
    left: A,
    right: B,
}

impl<A, B> Iterator for PureZip<A, B>
where
    A: ExactSizeIterator,
    B: ExactSizeIterator,
{
    type Item = (<A as Iterator>::Item, <B as Iterator>::Item);

    fn next(&mut self) -> Option<Self::Item> {
        if self.left.len() > 0 && self.right.len() > 0 {
            Some((self.left.next().unwrap(), self.right.next().unwrap()))
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len(), Some(self.len()))
    }
}

impl<A, B> ExactSizeIterator for PureZip<A, B>
where
    A: ExactSizeIterator,
    B: ExactSizeIterator,
{
    fn len(&self) -> usize {
        let left = self.left.len();
        let right = self.right.len();

        core::cmp::min(left, right)
    }
}

impl<A, B> core::iter::FusedIterator for PureZip<A, B>
where
    A: ExactSizeIterator,
    B: ExactSizeIterator,
{
}

trait PureZipExt: Sized {
    fn pure_zip<B: ExactSizeIterator>(self, other: B) -> PureZip<Self, B>;
}

impl<I: ExactSizeIterator> PureZipExt for I {
    /// See [`pure_zip`].
    fn pure_zip<B: ExactSizeIterator>(self, other: B) -> PureZip<I, B> {
        pure_zip(self, other)
    }
}
