//! The TFTP client implementation.

use core::error::Error;
use core::ffi::CStr;
use core::fmt::Display;

use crate::parser;
use crate::Ack;
use crate::Data;
use crate::DisplayExt as _;
use crate::ErrorCode;
use crate::Mode;
use crate::Opcode;
use crate::OpcodeBytes;
use crate::Packet;
use crate::ProtocolError;
use crate::Rwrq;
use crate::RwrqBytes;
use crate::TooLongError;
use crate::BLOCK_SIZE;
use crate::PACKET_SIZE;

use nom::Parser as _;

/// The TFTP client file download implementation.
pub mod download {

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

/// The TFTP client file upload implementation.
pub mod upload {

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

/// An error that can occur during an [`upload`] or a [`download`].
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

/// An [`Error`] indicating that the peer terminated the TFTP transfer.
#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub struct PeerError<'message> {
    /// The TFTP error code.
    pub code: ErrorCode,
    /// The error message. Can be empty.
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

/// An [`Error`] indicating an illegal filename.
#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub struct FilenameError<'filename> {
    /// The illegal filename.
    pub filename: &'filename CStr,
    /// Specifies why the `filename` is illegal.
    pub kind: FilenameErrorKind,
}

impl<'filename> Display for FilenameError<'filename> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "illegal filename '{}'", self.filename.display())
    }
}

/// The possible reasons why a filename might be illegal.
///
/// Used in the [`FilenameError`] type.
#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
#[non_exhaustive]
pub enum FilenameErrorKind {
    /// The filename is too long.
    TooLong(TooLongError),
}

impl From<TooLongError> for FilenameErrorKind {
    fn from(too_long: TooLongError) -> Self {
        FilenameErrorKind::TooLong(too_long)
    }
}
