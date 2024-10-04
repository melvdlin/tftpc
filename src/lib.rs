use core::fmt::{Debug, Display};

type IntoIter<T> = <T as IntoIterator>::IntoIter;
type CStrBytes<'a> = core::iter::Chain<core::str::Bytes<'a>, core::iter::Once<u8>>;

pub const BLOCK_SIZE: usize = 512;
pub const HEADER_SIZE: usize = 4;
pub const PACKET_SIZE: usize = BLOCK_SIZE + HEADER_SIZE;

pub enum Download {}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolError<'a> {
    kind: ProtocolErrorKind,
    message: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            Packet::Rrq(rwrq) | Packet::Wrq(rwrq) => PacketBytes::Rwrq(rwrq.bytes()),
            Packet::Data(data) => PacketBytes::Data(data.bytes()),
            Packet::Ack(ack) => PacketBytes::Ack(ack.bytes()),
            Packet::Error(error) => PacketBytes::Error(error.bytes()),
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
            PacketBytes::Rwrq(rwrq_bytes) => rwrq_bytes.next(),
            PacketBytes::Data(data_bytes) => data_bytes.next(),
            PacketBytes::Ack(ack_bytes) => ack_bytes.next(),
            PacketBytes::Error(error_bytes) => error_bytes.next(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Data<'a> {
    block_no: u16,
    data: &'a [u8],
}

impl<'a> Data<'a> {
    pub fn bytes(&self) -> DataBytes {
        DataBytes::new(self)
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MalformedPacket;

impl core::error::Error for MalformedPacket {}

impl Display for MalformedPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "malformed packet")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            1 => Self::Rrq,
            2 => Self::Wrq,
            3 => Self::Data,
            4 => Self::Ack,
            5 => Self::Error,
            n => return Err(UnknownOpcode(n)),
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownOpcode(pub u16);

impl core::error::Error for UnknownOpcode {}

impl Display for UnknownOpcode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "unknown opcode ({})", self.0)
    }
}

mod parser {

    use super::*;
    use branch::*;
    use bytes::streaming::*;
    use combinator::*;
    use nom::*;
    use number::streaming::be_u16;
    use sequence::tuple;

    pub fn parse_packet<'a>(
        block_size: usize,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Packet<'a>> {
        let opcode = |opcode| tag((opcode as u16).to_be_bytes());
        let cstr = || take_until(b"\0" as &[u8]);

        let rrq = map_res(
            tuple((opcode(Opcode::Rrq), cstr(), cstr())),
            |(_opcode, filename, mode)| {
                Ok::<_, core::str::Utf8Error>(Packet::Rrq(Rwrq {
                    filename: core::str::from_utf8(filename)?,
                    mode: core::str::from_utf8(mode)?,
                }))
            },
        );
        let wrq = map_res(
            tuple((opcode(Opcode::Wrq), cstr(), cstr())),
            |(_, filename, mode)| {
                Ok::<_, core::str::Utf8Error>(Packet::Wrq(Rwrq {
                    filename: core::str::from_utf8(filename)?,
                    mode: core::str::from_utf8(mode)?,
                }))
            },
        );
        let data = tuple((
            opcode(Opcode::Data),
            be_u16,
            take_while_m_n(0, block_size, |_| true),
        ))
        .map(|(_, block_no, data)| Packet::Data(Data { block_no, data }));
        let ack =
            tuple((opcode(Opcode::Ack), be_u16)).map(|(_, block_no)| Packet::Ack(Ack { block_no }));
        let error = map_res(
            tuple((opcode(Opcode::Error), be_u16, cstr())),
            |(_, error_code, message)| {
                Ok::<_, core::str::Utf8Error>(Packet::Error(Error {
                    error_code,
                    message: core::str::from_utf8(message)?,
                }))
            },
        );
        alt((rrq, wrq, data, ack, error))
    }
}
