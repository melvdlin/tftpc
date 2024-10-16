#![no_std]
#![allow(clippy::let_and_return)]
#![forbid(unsafe_code, unused_must_use)]

use core::error::Error;
use core::ffi::CStr;
use core::fmt::{Debug, Display};

type IntoIter<T> = <T as IntoIterator>::IntoIter;

pub const PACKET_SIZE: usize = HEADER_SIZE + BLOCK_SIZE;

const HEADER_SIZE: usize = OPCODE_SIZE + BLOCK_NO_SIZE;
const OPCODE_SIZE: usize = size_of::<u16>();
const BLOCK_NO_SIZE: usize = size_of::<u16>();

pub const BLOCK_SIZE: usize = 512;

pub mod download {

    use nom::Parser;

    use super::*;

    pub fn new<'filename>(
        tx: &mut [u8; PACKET_SIZE],
        filename: &'filename CStr,
        mode: Mode,
    ) -> Result<(AwaitingData, usize), NewDownloadError<'filename>> {
        write_rwrq(Opcode::Rrq, tx, filename, mode)
            .map(|written| (AwaitingData::new(), written))
            .map_err(NewDownloadError::from)
    }

    #[derive(Debug)]
    #[derive(Clone, Copy)]
    #[derive(PartialEq, Eq)]
    #[non_exhaustive]
    pub enum NewDownloadError<'a> {
        Filename(FilenameError<'a>),
    }

    impl<'a> Display for NewDownloadError<'a> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                f,
                "download initiation failed; cause: {}",
                match self {
                    | NewDownloadError::Filename(_) => "filename",
                }
            )
        }
    }

    impl<'a> Error for NewDownloadError<'a> {}

    impl<'filename> From<FilenameError<'filename>> for NewDownloadError<'filename> {
        fn from(filename: FilenameError<'filename>) -> Self {
            NewDownloadError::Filename(filename)
        }
    }

    #[derive(Debug)]
    #[derive(Clone, Copy)]
    #[derive(PartialEq, Eq)]
    pub struct AwaitingData {
        block_no: u16,
    }

    impl AwaitingData {
        const fn new() -> Self {
            AwaitingData { block_no: 1 }
        }

        pub fn process<'rx>(
            self,
            rx: &'rx [u8],
            tx: &mut [u8; PACKET_SIZE],
        ) -> (
            Result<BlockRecieved<'rx>, TransferError<'rx>>,
            Option<usize>,
        ) {
            let malformed_packet = (Err(TransferError::BadPacket), None);

            let Some((&[], packet)) = parser::packet().parse(rx).ok() else {
                return malformed_packet;
            };

            let Data { data, block_no } = match packet {
                | Packet::Data(data) => data,
                | Packet::Error(error) => return peer_terminated(error),
                | _ => return illegal_op(c"illegal operation", tx),
            };

            if data.len() > BLOCK_SIZE {
                return illegal_op(c"block too large", tx);
            }

            if block_no != self.block_no {
                // we ignore both smaller and greater block numbers to support wrapping
                return (Ok(BlockRecieved::Retransmission(self)), None);
            }

            let written =
                must_write(Packet::Ack(Ack { block_no }).bytes().unwrap(), tx, "ack");
            let received = if let Ok(intermediate) = <&[u8; BLOCK_SIZE]>::try_from(data) {
                BlockRecieved::Intermediate(
                    AwaitingData {
                        block_no: block_no.wrapping_add(1),
                    },
                    intermediate,
                )
            } else {
                BlockRecieved::Final(data)
            };

            (Ok(received), Some(written))
        }
    }

    // possible outcomes:
    // malformed packet  -> transfer failed (peer died), do nothing => BadPacket
    // protocol error    -> transfer failed (we died),   do nothing => PeerTerminated
    // illegal operation -> transfer failed (peer died), send error => BadPacket
    // bad block number  -> transfer failed (peer died), send error => BadPacket
    // full data block   -> data available,              send ack
    // small data block  -> transfer complete,           send ack

    #[derive(Debug)]
    pub enum BlockRecieved<'rx> {
        Intermediate(AwaitingData, &'rx [u8; BLOCK_SIZE]),
        Final(&'rx [u8]),
        Retransmission(AwaitingData),
    }
}

pub mod upload {
    use nom::Parser;

    use super::*;

    pub fn new<'filename>(
        tx: &mut [u8; PACKET_SIZE],
        filename: &'filename CStr,
        mode: Mode,
    ) -> Result<(AwaitingAck, usize), NewUploadError<'filename>> {
        write_rwrq(Opcode::Wrq, tx, filename, mode)
            .map(|written| (AwaitingAck::new(), written))
            .map_err(NewUploadError::from)
    }

    #[derive(Debug)]
    #[non_exhaustive]
    pub enum NewUploadError<'a> {
        Filename(FilenameError<'a>),
    }

    impl<'a> Display for NewUploadError<'a> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                f,
                "download initiation failed; cause: {}",
                match self {
                    | NewUploadError::Filename(_) => "filename",
                }
            )
        }
    }

    impl<'a> Error for NewUploadError<'a> {}

    impl<'filename> From<FilenameError<'filename>> for NewUploadError<'filename> {
        fn from(filename: FilenameError<'filename>) -> Self {
            NewUploadError::Filename(filename)
        }
    }

    #[derive(Debug)]
    #[derive(Clone, Copy)]
    #[derive(PartialEq, Eq)]
    pub struct AwaitingAck {
        block_no: u16,
    }

    impl AwaitingAck {
        const fn new() -> Self {
            AwaitingAck { block_no: 0 }
        }

        pub fn process<'rx>(
            self,
            rx: &'rx [u8],
            tx: &mut [u8; PACKET_SIZE],
            data: impl IntoIterator<Item = u8, IntoIter: ExactSizeIterator>,
        ) -> (Result<AckReceived, TransferError<'rx>>, Option<usize>) {
            let malformed_packet = (Err(TransferError::BadPacket), None);

            let Some((&[], packet)) = parser::packet().parse(rx).ok() else {
                return malformed_packet;
            };

            let Ack { block_no } = match packet {
                | Packet::Ack(ack) => ack,
                | Packet::Error(error) => return peer_terminated(error),
                | _ => return illegal_op(c"illegal operation", tx),
            };

            if block_no != self.block_no {
                // we ignore both smaller and greater block numbers to support wrapping
                return (Ok(AckReceived::Retransmission(self)), None);
            }

            let data = data.into_iter().take(BLOCK_SIZE);
            if data.len() == 0 {
                return (Ok(AckReceived::TransferComplete), None);
            }

            let mut tx = tx.iter_mut();

            let block_no = self.block_no.wrapping_add(1);

            let written =
                must_write(OpcodeBytes::new(Opcode::Data), tx.by_ref(), "data opcode")
                    + must_write(block_no.to_be_bytes(), tx.by_ref(), "block number")
                    + must_write(data, tx.by_ref(), "data block");

            (
                Ok(AckReceived::NextBlock(AwaitingAck { block_no })),
                Some(written),
            )
        }
    }

    // possible outcomes:
    // malformed packet                     -> transfer failed (peer died), do nothing => BadPacket
    // protocol error                       -> transfer failed (we died),   do nothing => PeerTerminated
    // illegal operation                    -> transfer failed (peer died), send error => BadPacket
    // bad block number                     -> retransmission,              do nothing => Retransmission
    // correct block number, data available -> send next block                         => NextBlock
    // correct block number, no more data   -> transfer complete                       => TransferComplete

    #[derive(Debug)]
    pub enum AckReceived {
        NextBlock(AwaitingAck),
        TransferComplete,
        Retransmission(AwaitingAck),
    }

    #[derive(Debug)]
    #[derive(Clone, Copy)]
    #[derive(PartialEq, Eq)]
    #[non_exhaustive]
    pub enum UploadError<'rx> {
        BadPacket,
        Peer(PeerError<'rx>),
    }

    impl<'a> Display for UploadError<'a> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                f,
                "download failed: {}",
                match self {
                    | UploadError::BadPacket => "malformed packet",
                    | UploadError::Peer(_) => "peer terminated connection",
                }
            )
        }
    }

    impl<'rx> Error for UploadError<'rx> {}
}

fn illegal_op<'message, T>(
    message: &'message CStr,
    tx: &mut [u8; PACKET_SIZE],
) -> (Result<T, TransferError<'message>>, Option<usize>) {
    (
        Err(TransferError::BadPacket),
        Some(must_write(
            Packet::Error(ProtocolError {
                code: ErrorCode::IllegalOperation,
                message,
            })
            .bytes()
            .expect("message too long"),
            tx,
            "error",
        )),
    )
}

fn peer_terminated<T>(error: ProtocolError) -> (Result<T, TransferError>, Option<usize>) {
    (Err(TransferError::Peer(error.into())), None)
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
#[non_exhaustive]
pub enum TransferError<'rx> {
    BadPacket,
    Peer(PeerError<'rx>),
}

impl<'a> Display for TransferError<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "download failed: {}",
            match self {
                | TransferError::BadPacket => "malformed packet",
                | TransferError::Peer(_) => "peer terminated connection",
            }
        )
    }
}

impl<'rx> Error for TransferError<'rx> {}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub struct PeerError<'message> {
    pub code: ErrorCode,
    pub message: &'message CStr,
}

impl<'message> Display for PeerError<'message> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "TFTP error: '{}' ({}), '{}'",
            self.code,
            self.code as u16,
            self.message.display(),
        )
    }
}

impl<'message> Error for PeerError<'message> {}

impl<'message> From<ProtocolError<'message>> for PeerError<'message> {
    fn from(error: ProtocolError<'message>) -> Self {
        Self {
            code: error.code,
            message: error.message,
        }
    }
}

fn write_rwrq<'filename>(
    opcode: Opcode,
    tx: &mut [u8; PACKET_SIZE],
    filename: &'filename CStr,
    mode: Mode,
) -> Result<usize, FilenameError<'filename>> {
    debug_assert!(matches!(opcode, Opcode::Rrq | Opcode::Wrq));

    let rwrq = Rwrq {
        filename,
        mode: mode.as_cstr(),
    };
    let mut rwrq_bytes = RwrqBytes::new(&rwrq).map_err(|e| FilenameError {
        filename,
        kind: e.into(),
    })?;
    debug_assert!(is_netascii(rwrq_bytes.mode().clone()));

    let mut tx_bytes = tx.iter_mut();
    let mut opcode_bytes = OpcodeBytes::new(opcode);
    must_write(opcode_bytes.by_ref(), tx_bytes.by_ref(), "rrq opcode");

    debug_assert_eq!(rwrq_bytes.filename().len(), filename.to_bytes().len());
    for (buf, byte) in tx_bytes.by_ref().zip(rwrq_bytes.by_ref()) {
        *buf = byte;
    }

    if rwrq_bytes.len() > 0 {
        let filename_len = filename.count_bytes();
        // the packet should be significantly larger
        // than the opcode and the mode combined
        debug_assert!(
            filename_len > 0,
            "cannot fit filename null terminator into packet; this is a bug"
        );

        Err(FilenameError {
            filename,
            kind: TooLongError {
                actual_len: Some(filename_len),
                max_len: filename_len - rwrq_bytes.len(),
            }
            .into(),
        })
    } else {
        let unwritten = tx_bytes.len();
        let written = tx.len() - unwritten;
        Ok(written)
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

fn must_write<'tx>(
    bytes: impl IntoIterator<Item = u8, IntoIter: ExactSizeIterator>,
    tx: impl IntoIterator<Item = &'tx mut u8, IntoIter: ExactSizeIterator>,
    name: impl core::fmt::Display,
) -> usize {
    let mut bytes = bytes.into_iter();
    let mut tx_bytes = tx.into_iter();
    let tx_len = tx_bytes.len();
    for (buf, byte) in tx_bytes.by_ref().zip(bytes.by_ref()) {
        *buf = byte;
    }
    assert_eq!(bytes.len(), 0, "cannot fit `{name}` into TX buffer");

    let unwritten = tx_bytes.len();
    let written = tx_len - unwritten;
    written
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub struct FilenameError<'filename> {
    pub filename: &'filename CStr,
    pub kind: FilenameErrorKind,
}

impl<'filename> Display for FilenameError<'filename> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "illegal filename '{}'", self.filename.display())
    }
}

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
#[non_exhaustive]
pub enum FilenameErrorKind {
    TooLong(TooLongError),
}

impl From<TooLongError> for FilenameErrorKind {
    fn from(too_long: TooLongError) -> Self {
        FilenameErrorKind::TooLong(too_long)
    }
}

/// An [`Error`](Error) type indicating that a sequence of data exceeds some maximum length.
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
pub struct BufferTooSmall {
    pub required_size: usize,
    pub actual_size: usize,
}

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

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub struct UnknownErrorCode(pub u16);

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
            | Packet::Ack(_) => Opcode::Data,
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

    pub fn filename(&mut self) -> &mut (impl ExactSizeIterator<Item = u8> + Clone + 'a) {
        &mut self.filename
    }

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

#[derive(Debug)]
#[derive(Clone)]
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
struct ErrorBytes<'a> {
    error_code: IntoIter<[u8; 2]>,
    message: CStrBytes<'a>,
}

impl<'a> ErrorBytes<'a> {
    /// Returns an error iff the error payload would yield more than `usize::MAX` bytes
    pub fn new(error: &'a ProtocolError) -> Result<Self, TooLongError> {
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

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub struct UnknownOpcode(pub u16);

impl Error for UnknownOpcode {}

impl Display for UnknownOpcode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "unknown opcode ({})", self.0)
    }
}

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

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub struct UnknownMode<'a>(&'a CStr);

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
        use nom::InputTake;

        move |i: &[u8]| {
            let Some(nul_pos) = i.find_substring(b"\0".as_slice()) else {
                return Err(nom::Err::Incomplete(nom::Needed::Unknown));
            };

            let (cstr, rest) = i.take_split(nul_pos + 1);
            let cstr = CStr::from_bytes_with_nul(cstr)
                .expect("only nul byte should be at index + 1");
            Ok((rest, cstr))
        }
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

impl DisplayExt for &CStr {
    fn display(&self) -> impl Display {
        DisplayCStr(self)
    }
}
