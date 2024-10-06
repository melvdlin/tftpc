use core::fmt::{Debug, Display};

type IntoIter<T> = <T as IntoIterator>::IntoIter;
type CStrBytes<'a> = core::iter::Chain<core::str::Bytes<'a>, core::iter::Once<u8>>;

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
        pub fn new(
            packet: &mut [u8; PACKET_SIZE],
            filename: &str,
            mode: Encoding,
        ) -> Self {
            Packet::Rrq(Rwrq {
                filename: filename,
                mode: todo!(),
            });

            todo!()
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
#[non_exhaustive]
pub enum Encoding {
    Netascii,
    Octect,
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub struct FilenameError<'a> {
    pub filename: &'a str,
    pub kind: FilenameErrorKind,
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
#[non_exhaustive]
pub enum FilenameErrorKind {
    // NullByte(NullByte),
    Encoding(Encoding),
}

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
enum Packet<'a> {
    Rrq(Rwrq<'a>),
    Wrq(Rwrq<'a>),
    Data(Data<'a>),
    Ack(Ack),
    Error(Error<'a>),
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
    filename: &'a str,
    mode: &'a str,
}

impl<'a> Rwrq<'a> {
    pub fn bytes(&self) -> RwrqBytes {
        RwrqBytes::new(self)
    }
}

struct RwrqBytes<'a> {
    inner: core::iter::Chain<CStrBytes<'a>, CStrBytes<'a>>,
}

impl<'a> RwrqBytes<'a> {
    pub fn new(rwrq: &'a Rwrq) -> Self {
        RwrqBytes {
            inner: rwrq
                .filename
                .bytes()
                .chain(core::iter::once(0))
                .chain(rwrq.mode.bytes().chain(core::iter::once(b'\0'))),
        }
    }
}

impl<'a> Iterator for RwrqBytes<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
struct Data<'a> {
    block_no: u16,
    data: &'a [u8],
}

impl<'a> Data<'a> {
    pub fn bytes(&self) -> DataBytes {
        DataBytes::new(self)
    }
}

#[derive(Debug)]
#[derive(Clone)]
struct DataBytes<'a> {
    inner: core::iter::Chain<IntoIter<[u8; 2]>, core::iter::Copied<IntoIter<&'a [u8]>>>,
}

impl<'a> DataBytes<'a> {
    pub fn new(data: &'a Data) -> Self {
        DataBytes {
            inner: data
                .block_no
                .to_be_bytes()
                .into_iter()
                .chain(data.data.iter().copied()),
        }
    }
}

impl<'a> Iterator for DataBytes<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
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
    inner: IntoIter<[u8; 2]>,
}

impl AckBytes {
    pub fn new(ack: &Ack) -> Self {
        Self {
            inner: ack.block_no.to_be_bytes().into_iter(),
        }
    }
}

impl Iterator for AckBytes {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
struct Error<'a> {
    error_code: u16,
    message: &'a str,
}

impl<'a> Error<'a> {
    pub fn bytes(&self) -> ErrorBytes {
        ErrorBytes::new(self)
    }
}

struct ErrorBytes<'a> {
    inner: core::iter::Chain<IntoIter<[u8; 2]>, CStrBytes<'a>>,
}

impl<'a> ErrorBytes<'a> {
    pub fn new(error: &'a Error) -> Self {
        Self {
            inner: error
                .error_code
                .to_be_bytes()
                .into_iter()
                .chain(error.message.bytes().chain(core::iter::once(b'\0'))),
        }
    }
}

impl<'a> Iterator for ErrorBytes<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
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
                Ok::<_, core::str::Utf8Error>(Rwrq {
                    filename: core::str::from_utf8(filename)?,
                    mode: core::str::from_utf8(mode)?,
                })
            },
        )
    }

    pub fn rwq<'a>() -> impl Parser<&'a [u8], Rwrq<'a>, nom::error::Error<&'a [u8]>> {
        map_res(
            preceded(opcode(Opcode::Wrq), tuple((cstr(), cstr()))),
            |(filename, mode)| {
                Ok::<_, core::str::Utf8Error>(Rwrq {
                    filename: core::str::from_utf8(filename)?,
                    mode: core::str::from_utf8(mode)?,
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
    ) -> impl Parser<&'a [u8], &'a [u8], nom::error::Error<&'a [u8]>> {
        tag((opcode as u16).to_be_bytes())
    }

    fn cstr<'a>() -> impl Parser<&'a [u8], &'a [u8], nom::error::Error<&'a [u8]>> {
        take_until(b"\0" as &[u8])
    }

    pub fn parse_mode<'a>() -> impl Parser<&'a [u8], Encoding, nom::error::Error<&'a [u8]>>
    {
        let netascii = value(Encoding::Netascii, tag_no_case("netascii"));
        let octet = value(Encoding::Octect, tag_no_case("octet"));

        alt((netascii, octet))
    }
}
