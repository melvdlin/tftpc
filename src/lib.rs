use core::fmt::{Debug, Display};
use std::{ffi::CStr, usize};

type IntoIter<T> = <T as IntoIterator>::IntoIter;

pub const BLOCK_SIZE: usize = 512;
pub const HEADER_SIZE: usize = 4;
pub const PACKET_SIZE: usize = BLOCK_SIZE + HEADER_SIZE;

pub mod download {
    use super::*;
    pub enum Download {
        PreInit(PreInit),
    }

    struct PreInit {}

    impl Download {
        pub fn new<'filename>(
            packet: &mut [u8; PACKET_SIZE],
            filename: &'filename str,
            mode: Encoding,
        ) -> Result<Self, NewDownloadError<'filename>> {
            if let Some(position) = filename.bytes().position(|c| c == b'\0') {
                return Err(NewDownloadError {
                    kind: NewDownloadErrorKind::Filename(FilenameError {
                        filename,
                        kind: FilenameErrorKind::NullByte(NullByteError { position }),
                    }),
                });
            }

            let rwrq = Rwrq {
                filename,
                mode: mode.as_str(),
            };

            debug_assert!(is_netascii(rwrq.mode.bytes()));

            let opcode_bytes = (Opcode::Rrq as u16).to_be_bytes();
            let (opcode_buf, rest) = packet.split_at_mut(opcode_bytes.len());
        }
    }

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct NewDownloadError<'a> {
        pub kind: NewDownloadErrorKind<'a>,
    }

    #[derive(Debug)]
    #[non_exhaustive]
    pub enum NewDownloadErrorKind<'a> {
        Filename(FilenameError<'a>),
    }

    impl<'filename> From<FilenameError<'filename>> for NewDownloadErrorKind<'filename> {
        fn from(filename: FilenameError<'filename>) -> Self {
            NewDownloadErrorKind::Filename(filename)
        }
    }

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct DownloadError<'a> {
        pub kind: DownloadErrorKind<'a>,
    }

    #[derive(Debug)]
    #[non_exhaustive]
    pub enum DownloadErrorKind<'a> {
        Protocol(ProtocolError<'a>),
        TransferComplete,
    }
}

fn is_netascii(bytes: impl IntoIterator<Item = u8> + Clone) -> bool {
    let mut netascii = netascii::Netascii::from_bytes(bytes.clone());
    let mut bytes = bytes.into_iter();
    while let [Some(netascii), Some(bytes)] = [netascii.next(), bytes.next()] {
        if netascii != bytes {
            return false;
        }
    }

    netascii.next().is_none() && bytes.next().is_none()
}

pub mod upload {
    use super::*;
    pub enum Upload {}

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct UploadError<'a> {
        pub kind: UploadErrorKind<'a>,
    }

    #[derive(Debug)]
    #[non_exhaustive]
    pub enum UploadErrorKind<'a> {
        Protocol(ProtocolError<'a>),
    }
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub struct FilenameError<'filename> {
    pub filename: &'filename str,
    pub kind: FilenameErrorKind,
}

impl<'filename> Display for FilenameError<'filename> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "illegal filename '{}'", self.filename)
    }
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
#[non_exhaustive]
pub enum FilenameErrorKind {
    NullByte(NullByteError),
    TooLong(TooLongError),
}

impl From<NullByteError> for FilenameErrorKind {
    fn from(null_byte: NullByteError) -> Self {
        FilenameErrorKind::NullByte(null_byte)
    }
}

impl From<TooLongError> for FilenameErrorKind {
    fn from(too_long: TooLongError) -> Self {
        FilenameErrorKind::TooLong(too_long)
    }
}

/// An [`Error`](core::error::Error) type indicating that a byte string contains an illegal null byte.
#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub struct NullByteError {
    position: usize,
}

impl Display for NullByteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "sequence contains an illegal null byte at position {}",
            self.position
        )
    }
}

impl core::error::Error for NullByteError {}

/// An [`Error`](core::error::Error) type indicating that a sequence of data exceeds some maximum length.
#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub struct TooLongError {
    pub actual_len: Option<usize>,
    pub max_len: usize,
}

impl Display for TooLongError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

impl core::error::Error for TooLongError {}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub struct BufferTooSmall {
    pub required_size: usize,
    pub actual_size: usize,
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub struct ProtocolError<'a> {
    kind: ProtocolErrorKind,
    message: &'a str,
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub enum ProtocolErrorKind {
    Undefined,
    FileNotFound,
    AccessViolation,
    DiskFull,
    IllegalOperation,
    UnknownTransferID,
    FileAlreadyExists,
    NoSuchUser,
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
enum Packet<'buf> {
    Rrq(Rwrq<'buf>),
    Wrq(Rwrq<'buf>),
    Data(Data<'buf>),
    Ack(Ack),
    Error(Error<'buf>),
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

impl<'buf> From<Error<'buf>> for Packet<'buf> {
    fn from(error: Error<'buf>) -> Self {
        Packet::Error(error)
    }
}

impl<'a> Packet<'a> {
    #[allow(unused)]
    pub fn bytes(&self) -> PacketBytes {
        match self {
            | Packet::Rrq(rwrq) | Packet::Wrq(rwrq) => PacketBytes::Rwrq(rwrq.bytes()),
            | Packet::Data(data) => PacketBytes::Data(data.bytes()),
            | Packet::Ack(ack) => PacketBytes::Ack(ack.bytes()),
            | Packet::Error(error) => PacketBytes::Error(error.bytes()),
        }
    }
}

enum PacketBytes<'a> {
    Rwrq(RwrqBytes<'a>),
    Data(DataBytes<'a>),
    Ack(AckBytes),
    Error(ErrorBytes<'a>),
}

impl<'a> Iterator for PacketBytes<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            | PacketBytes::Rwrq(rwrq_bytes) => rwrq_bytes.next(),
            | PacketBytes::Data(data_bytes) => data_bytes.next(),
            | PacketBytes::Ack(ack_bytes) => ack_bytes.next(),
            | PacketBytes::Error(error_bytes) => error_bytes.next(),
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

struct RwrqBytes<'a> {
    filename: CStrBytes<'a>,
    mode: CStrBytes<'a>,
}

impl<'a> RwrqBytes<'a> {
    pub fn new(rwrq: &'a Rwrq) -> Result<Self, RwrqBytesError> {
        let filename = CStrBytes::from_cstr(rwrq.filename);
        let mode = CStrBytes::from_cstr(rwrq.mode);

        if filename.len().checked_add(mode.len()).is_none() {
            return Err(RwrqBytesError::TooLong(TooLongError {
                actual_len: None,
                max_len: usize::MAX,
            }));
        }

        Ok(Self { filename, mode })
    }

    pub fn filename(&mut self) -> &mut (impl ExactSizeIterator<Item = u8> + 'a) {
        &mut self.filename
    }

    pub fn mode(&mut self) -> &mut (impl ExactSizeIterator<Item = u8> + 'a) {
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

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
enum RwrqBytesError {
    TooLong(TooLongError),
}

impl Display for RwrqBytesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "`RwrqBytes` creation failed (cause: {})",
            match self {
                | RwrqBytesError::TooLong(_) => "combined length of filename and mode",
            }
        )
    }
}

impl core::error::Error for RwrqBytesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            | RwrqBytesError::TooLong(e) => e,
        })
    }
}

struct CStrBytes<'str> {
    cstr: &'str [u8],
    next: Option<usize>,
}

impl<'str> CStrBytes<'str> {
    pub fn from_cstr(cstr: &'str CStr) -> Self {
        Self {
            cstr: cstr.to_bytes(),
            next: Some(0),
        }
    }
}

impl<'str> Iterator for CStrBytes<'str> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.next?;
        let next_byte = self.cstr.get(next).copied();
        if next_byte.is_some() {
            self.next = next.checked_add(1);
        }
        next_byte
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl<'str> ExactSizeIterator for CStrBytes<'str> {
    fn len(&self) -> usize {
        let Some(next) = self.next else { return 0 };
        self.cstr.len() - next
    }
}

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

    pub fn block_no(&mut self) -> &mut impl ExactSizeIterator<Item = u8> {
        &mut self.block_no
    }

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

impl Ack {
    pub fn bytes(&self) -> AckBytes {
        AckBytes::new(self)
    }
}

struct AckBytes {
    block_no: IntoIter<[u8; 2]>,
}

impl AckBytes {
    pub fn new(ack: &Ack) -> Self {
        Self {
            block_no: ack.block_no.to_be_bytes().into_iter(),
        }
    }

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
struct Error<'a> {
    error_code: u16,
    message: &'a CStr,
}

struct ErrorBytes<'a> {
    error_code: IntoIter<[u8; 2]>,
    message: CStrBytes<'a>,
}

impl<'a> ErrorBytes<'a> {
    pub fn new(error: &'a Error) -> Result<Self, TooLongError> {
        let error_code = error.error_code.to_be_bytes().into_iter();
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

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
struct MalformedPacket;

impl core::error::Error for MalformedPacket {}

impl Display for MalformedPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "malformed packet")
    }
}

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

    fn try_from(opcode: u16) -> Result<Self, UnknownOpcode> {
        Ok(match opcode {
            | 1 => Self::Rrq,
            | 2 => Self::Wrq,
            | 3 => Self::Data,
            | 4 => Self::Ack,
            | 5 => Self::Error,
            | n => return Err(UnknownOpcode(n)),
        })
    }
}
#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub struct UnknownOpcode(pub u16);

impl core::error::Error for UnknownOpcode {}

impl Display for UnknownOpcode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "unknown opcode ({})", self.0)
    }
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
#[non_exhaustive]
pub enum Encoding {
    Netascii,
    Octect,
}

impl Encoding {
    pub const fn as_str(self) -> &'static str {
        match self {
            | Encoding::Netascii => "netascii",
            | Encoding::Octect => "octet",
        }
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

    pub fn parse_packet<'a>() -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Packet<'a>> {
        let rrq = rrq().map(Packet::Rrq);
        let wrq = wrq().map(Packet::Wrq);
        let data = data().map(Packet::Data);
        let ack = ack().map(Packet::Ack);
        let error = error().map(Packet::Error);

        alt((rrq, wrq, data, ack, error))
    }

    pub fn rrq<'a>() -> impl Parser<&'a [u8], Rwrq<'a>, nom::error::Error<&'a [u8]>> {
        map_res(
            preceded(opcode(Opcode::Rrq), tuple((cstr(), cstr()))),
            |(filename, mode)| {
                Ok::<_, core::ffi::FromBytesWithNulError>(Rwrq {
                    filename: CStr::from_bytes_with_nul(filename)?,
                    mode: CStr::from_bytes_with_nul(mode)?,
                })
            },
        )
    }

    pub fn wrq<'a>() -> impl Parser<&'a [u8], Rwrq<'a>, nom::error::Error<&'a [u8]>> {
        map_res(
            preceded(opcode(Opcode::Wrq), tuple((cstr(), cstr()))),
            |(filename, mode)| {
                Ok::<_, core::ffi::FromBytesWithNulError>(Rwrq {
                    filename: CStr::from_bytes_with_nul(filename)?,
                    mode: CStr::from_bytes_with_nul(mode)?,
                })
            },
        )
    }

    pub fn data<'a>() -> impl Parser<&'a [u8], Data<'a>, nom::error::Error<&'a [u8]>> {
        preceded(opcode(Opcode::Data), tuple((be_u16, rest)))
            .map(|(block_no, data)| Data { block_no, data })
    }

    pub fn ack<'a>() -> impl Parser<&'a [u8], Ack, nom::error::Error<&'a [u8]>> {
        preceded(opcode(Opcode::Ack), be_u16).map(|block_no| Ack { block_no })
    }

    pub fn error<'a>() -> impl Parser<&'a [u8], Error<'a>, nom::error::Error<&'a [u8]>> {
        map_res(
            preceded(opcode(Opcode::Error), tuple((be_u16, cstr()))),
            |(error_code, message)| {
                Ok::<_, core::str::Utf8Error>(Error {
                    error_code,
                    message: core::str::from_utf8(message)?,
                })
            },
        )
    }

    fn opcode<'a>(
        opcode: Opcode,
    ) -> impl Parser<&'a [u8], Opcode, nom::error::Error<&'a [u8]>> {
        value(opcode, tag((opcode as u16).to_be_bytes()))
    }

    fn cstr<'a>() -> impl Parser<&'a [u8], &'a [u8], nom::error::Error<&'a [u8]>> {
        todo!("include nul byte");
        take_until(b"\0" as &[u8])
    }

    pub fn mode<'a>(
        mode: Encoding,
    ) -> impl Parser<&'a str, Encoding, nom::error::Error<&'a str>> {
        value(mode, tag_no_case(mode.as_str()))
    }

    pub fn parse_mode<'a>() -> impl Parser<&'a str, Encoding, nom::error::Error<&'a str>>
    {
        let netascii = mode(Encoding::Netascii);
        let octet = mode(Encoding::Octect);

        alt((netascii, octet))
    }
}
