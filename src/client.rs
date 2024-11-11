//! The TFTP client implementation.

use core::error::Error;
use core::ffi::CStr;
use core::fmt::Debug;
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
use crate::PureZipExt as _;
use crate::Rwrq;
use crate::RwrqBytes;
use crate::TooLongError;
use crate::BLOCK_SIZE;
use crate::PACKET_SIZE;

use nom::Parser as _;

/// The TFTP client file download implementation.
///
/// # Examples
///
/// A simple event loop to drive a download transaction:
/// ```no_run
/// use core::error::Error;
/// use core::ffi::CStr;
/// use std::net::UdpSocket;
///
/// use ttftp::client::download::*;
/// use ttftp::client::download;
/// use ttftp::client::TransferError;
/// use ttftp::Mode;
///
/// fn download(
///     filename: &CStr,
///     sock: UdpSocket,
///     tx: &mut [u8; ttftp::PACKET_SIZE],
///     rx: &mut [u8; ttftp::PACKET_SIZE],
/// ) -> Result<Vec<u8>, Box<dyn Error>> {
///     let mut file = Vec::<u8>::new();
///
///     let mut state;
///     let send;
///     (state, send) = download::new(tx, &filename, Mode::Octect).unwrap();
///
///     loop {
///         sock.send(&tx[..send])?;
///         let received = sock.recv(rx)?;
///
///         let (result, send) = state.process(&rx[..received], tx);
///
///         if let Some(send) = send {
///             sock.send(&tx[..send])?;
///         }
///
///         // strip out error message to promote the error to 'static
///         // this would not be required with polonius
///         state = match result.map_err(TransferError::strip)? {
///             | BlockReceived::Intermediate(awaiting_data, block) => {
///                 file.extend_from_slice(block);
///                 awaiting_data
///             }
///             | BlockReceived::Final(block) => {
///                 file.extend_from_slice(block);
///                 break;
///             }
///             | BlockReceived::Retransmission(state) => state,
///         }
///     }
///
///     Ok(file)
/// }
/// ```
pub mod download {

    use super::*;

    /// Writes to the provided `tx` buffer
    /// a packet requesting a download of the file specified by `filename`,
    /// to be transferred in the specified [`Mode`].
    ///
    /// Returns a state object that is able to process responses to this request packet,
    /// and the size of the request packet on success, and a [`FilenameError`] otherwise.
    ///
    /// Note that the filename is encoded into Netascii, and any filename length related errors
    /// refer to its encoded length.
    /// Users generally need not concern themselves with this encoding,
    /// since it only matters if the filename contains carriage return (CR) characters.
    pub fn new<'filename>(
        tx: &mut [u8; PACKET_SIZE],
        filename: &'filename CStr,
        mode: Mode,
    ) -> Result<(AwaitingData, usize), FilenameError<'filename>> {
        write_rwrq(Opcode::Rrq, tx, filename, mode)
            .map(|written| (AwaitingData::new(), written))
    }

    /// A state object able to process packets received from a TFTP server
    /// as part of a download transfer.
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

        /// Process the packet in the `rx` buffer received from a TFTP server
        /// as part of a download transfer
        /// and potentially write an appropriate response into the provided `tx` buffer.
        ///
        ///
        /// Returns the size of the response packet, if one should be sent,
        /// and the status of the transfer.
        ///
        ///
        /// A [`TransferError`] indicates that the download failed, and why.
        ///
        ///
        /// A [`BlockReceived`] indicates that the download is either still in progress,
        /// or successfully finished:
        ///
        /// - [`Intermediate`](BlockReceived::Intermediate)
        ///   indicates that a block of data has been received,
        ///   but more are expected still.
        ///
        /// - [`Final`](BlockReceived::Final)
        ///   indicates that the final block of data has been received
        ///   and the download is finished.
        ///
        /// - [`Retransmission`](BlockReceived::Retransmission)
        ///   indicates that a block of data has been received,
        ///   but did not match the expected block number
        ///   and is thus discarded as a retransmission.
        pub fn process<'rx>(
            self,
            rx: &'rx [u8],
            tx: &mut [u8; PACKET_SIZE],
        ) -> (
            Result<BlockReceived<'rx>, TransferError<'rx>>,
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
                return (Ok(BlockReceived::Retransmission(self)), None);
            }

            let written =
                must_write(Packet::Ack(Ack { block_no }).bytes().unwrap(), tx, "ack");
            let received = if let Ok(intermediate) = <&[u8; BLOCK_SIZE]>::try_from(data) {
                BlockReceived::Intermediate(
                    AwaitingData {
                        block_no: block_no.wrapping_add(1),
                    },
                    intermediate,
                )
            } else {
                BlockReceived::Final(data)
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

    /// The result of processing a packet received from a TFTP server
    /// as part of a download transfer.
    ///
    /// See [`AwaitingData::process`] for details.
    #[derive(Debug)]
    pub enum BlockReceived<'rx> {
        /// Indicates that a block of data has been received,
        /// but more are expected still.
        Intermediate(AwaitingData, &'rx [u8; BLOCK_SIZE]),
        /// indicates that the final block of data has been received,
        /// and the download is finished.
        Final(&'rx [u8]),
        /// indicates that a block of data has been received,
        /// but did not match the expected block number
        /// and is thus discarded as a retransmission.
        Retransmission(AwaitingData),
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_new_octet() {
            let filename = c"foo_bar.txt";
            let mut buf = [0u8; PACKET_SIZE];

            let result = download::new(&mut buf, filename, Mode::Octect).unwrap();
            assert!(matches!(result, (AwaitingData { block_no: 1 }, _)));

            let (opcode, rest) = buf[..result.1].split_at(size_of::<u16>());
            assert_eq!(opcode, 1u16.to_be_bytes());
            let (filename_bytes, mode) =
                rest.split_at(rest.iter().position(|char| *char == b'\0').unwrap() + 1);
            assert!(filename_bytes.eq_ignore_ascii_case(filename.to_bytes_with_nul()));
            assert!(mode.eq_ignore_ascii_case(c"octet".to_bytes_with_nul()))
        }

        #[test]
        fn test_new_netscii() {
            let filename = c"foo_bar.txt";
            let mut buf = [0u8; PACKET_SIZE];

            let result = download::new(&mut buf, filename, Mode::Netascii).unwrap();
            assert!(matches!(result, (AwaitingData { block_no: 1 }, _)));

            let (opcode, rest) = buf[..result.1].split_at(size_of::<u16>());
            assert_eq!(opcode, 1u16.to_be_bytes());
            let (filename_bytes, mode) =
                rest.split_at(rest.iter().position(|char| *char == b'\0').unwrap() + 1);
            assert!(filename_bytes.eq_ignore_ascii_case(filename.to_bytes_with_nul()));
            assert!(mode.eq_ignore_ascii_case(c"netascii".to_bytes_with_nul()))
        }

        #[test]
        fn test_new_long_filename() {
            let filename = &const {
                let mut filename = [b'a'; PACKET_SIZE];
                filename[PACKET_SIZE - 1] = b'\0';
                filename
            };
            let filename = CStr::from_bytes_with_nul(filename).unwrap();

            let mut buf = [0u8; PACKET_SIZE];
            let result = download::new(&mut buf, filename, Mode::Octect);
            assert!(matches!(
                result,
                Err(FilenameError {
                    kind: FilenameErrorKind::TooLong(_),
                    ..
                })
            ))
        }
    }
}

/// The TFTP client file upload implementation.
///
/// # Examples
///
/// A simple event loop to drive a upload transaction:
/// ```no_run
/// use core::error::Error;
/// use core::ffi::CStr;
/// use std::net::UdpSocket;
///
/// use ttftp::client::upload::*;
/// use ttftp::client::upload;
/// use ttftp::client::TransferError;
/// use ttftp::Mode;
///
/// fn upload<'filename>(
///     filename: &'filename CStr,
///     file: &[u8],
///     sock: UdpSocket,
///     tx: &mut [u8; ttftp::PACKET_SIZE],
///     rx: &mut [u8; ttftp::PACKET_SIZE],
/// ) -> Result<(), Box<dyn Error + 'filename>> where {
///     let mut state;
///     let send;
///     (state, send) = upload::new(tx, filename, Mode::Octect)?;
///
///     let mut data = file.iter().copied();
///     loop {
///         sock.send(&tx[..send])?;
///         let received = sock.recv(rx)?;
///
///         let (result, send) = state.process(&rx[..received], tx, data.by_ref());
///
///         if let Some(send) = send {
///             sock.send(&tx[..send])?;
///         }
///
///         state = match result.map_err(TransferError::strip)? {
///             | AckReceived::NextBlock(awaiting_ack) => awaiting_ack,
///             | AckReceived::TransferComplete => break,
///             | AckReceived::Retransmission(awaiting_ack) => {
///                 awaiting_ack
///             }
///         }
///     }
///
///     Ok(())
/// }
///
/// ```
pub mod upload {

    use super::*;

    /// Writes to the provided `tx` buffer
    /// a packet requesting an upwnload of the file specified by `filename`,
    /// to be transferred in the specified [`Mode`].
    ///
    /// Returns a state object that is able to process responses to this request packet,
    /// and the size of the request packet on success, and a [`FilenameError`] otherwise.
    ///
    /// Note that the filename is encoded into Netascii, and any filename length related errors
    /// refer to its encoded length.
    /// Users generally need not concern themselves with this encoding,
    /// since it only matters if the filename contains carriage return (CR) characters.
    pub fn new<'filename>(
        tx: &mut [u8; PACKET_SIZE],
        filename: &'filename CStr,
        mode: Mode,
    ) -> Result<(AwaitingAck, usize), FilenameError<'filename>> {
        write_rwrq(Opcode::Wrq, tx, filename, mode)
            .map(|written| (AwaitingAck::new(), written))
    }

    /// A state object able to process packets received from a TFTP server
    /// as part of an upload transfer.
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

        /// Process the packet in the `rx` buffer received from a TFTP server
        /// as part of an upwnload transfer
        /// and potentially write an appropriate response into the provided `tx` buffer.
        ///
        /// Takes a `data` iterator of the remaining data to be uploaded.
        /// This iterator should usually be passed by `&mut`,
        /// as this will advance the underlying iterator
        /// when data is taken out of it and written into the `tx` buffer.
        ///
        ///
        ///
        /// Returns the size of the response packet, if one should be sent,
        /// and the status of the transfer.
        ///
        ///
        /// A [`TransferError`] indicates that the upload failed, and why.
        ///
        ///
        /// An [`AckReceived`] indicates that the download is either still in progress,
        /// or successfully finished:
        ///
        /// - [`Intermediate`](AckReceived::NextBlock)
        ///   indicates that the last sent packet has been acknowledged,
        ///   and the next data packet should be sent.
        ///
        /// - [`TransferComplete`](AckReceived::TransferComplete)
        ///   indicates that the last sent packet has been acknowledged,
        ///   and the transfer is complete.
        ///
        /// - [`Retransmission`](AckReceived::Retransmission)
        ///   indicates that some  has been acknowledged,
        ///   but not the last sent one.
        ///   The acknowledgement is thus discarded as a retransmission.
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

    /// The result of processing a packet received from a TFTP server
    /// as part of an upload transfer.
    ///
    /// See [`AwaitingAck::process`] for details.
    #[derive(Debug)]
    pub enum AckReceived {
        NextBlock(AwaitingAck),
        TransferComplete,
        Retransmission(AwaitingAck),
    }
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

impl<'rx> TransferError<'rx> {
    pub fn strip(self) -> TransferError<'static> {
        match self {
            | TransferError::BadPacket => TransferError::BadPacket,
            | TransferError::Peer(peer_error) => {
                TransferError::Peer(peer_error.strip().0)
            }
        }
    }
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

impl<'message> PeerError<'message> {
    /// strip out the error message to promote the `self` to `'static`.
    pub fn strip(self) -> (PeerError<'static>, &'message CStr) {
        let Self { code, message } = self;
        (PeerError::from(code), message)
    }
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

impl<'message> From<ErrorCode> for PeerError<'message> {
    fn from(code: ErrorCode) -> Self {
        Self { code, message: c"" }
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
    debug_assert!(is_netascii(rwrq_bytes.filename().clone()));
    let filename_len = rwrq_bytes.filename().len();

    let mut tx_bytes = tx.iter_mut().peekable();
    let mut opcode_bytes = OpcodeBytes::new(opcode);
    must_write(opcode_bytes.by_ref(), tx_bytes.by_ref(), "rwrq opcode");

    for (buf, byte) in tx_bytes.by_ref().pure_zip(rwrq_bytes.by_ref()) {
        *buf = byte;
    }

    if rwrq_bytes.len() > 0 {
        // rwrq_bytes has not been fully consumed

        // the packet should be significantly larger
        // than the opcode and the mode combined
        debug_assert!(
            filename_len > 1,
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
    let mut counted = 0;

    for (byte, buf) in bytes.by_ref().pure_zip(tx_bytes.by_ref()) {
        *buf = byte;
        counted += 1;
    }
    assert_eq!(bytes.len(), 0, "cannot fit `{name}` into TX buffer");

    let unwritten = tx_bytes.len();
    let written = tx_len - unwritten;
    debug_assert_eq!(counted, written);
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

impl<'filename> Error for FilenameError<'filename> {}

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
