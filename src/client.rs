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
    #[derive(Hash)]
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
                | _ => {
                    return bad_packet(
                        ErrorCode::IllegalOperation,
                        c"illegal operation",
                        tx,
                    )
                }
            };

            if data.len() > BLOCK_SIZE {
                return bad_packet(ErrorCode::Undefined, c"block too large", tx);
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
    #[derive(Clone, Copy)]
    #[derive(PartialEq, Eq)]
    #[derive(Hash)]
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
        use macro_rules_attribute::apply;

        use crate::concat_arrays;
        use crate::infer_array_size;
        use crate::test_helpers::*;

        use super::*;

        #[apply(infer_array_size)]
        const LOREM_BYTES: [u8; _] = *include_bytes!("lorem.txt");
        const TX: [u8; PACKET_SIZE] = [0; PACKET_SIZE];

        #[test]
        fn test_new_octet() {
            let filename = c"foo_bar.txt";
            let mut tx = TX;

            let (result, tx_len) =
                download::new(&mut tx, filename, Mode::Octect).unwrap();
            assert_eq!(result, AwaitingData { block_no: 1 });

            let tx = &tx[..tx_len];
            let (opcode, rest) = tx.split_at(2);
            assert_eq!(opcode, 1u16.to_be_bytes());
            let (filename_bytes, mode) =
                rest.split_at(rest.iter().position(|char| *char == b'\0').unwrap() + 1);
            assert!(filename_bytes.eq_ignore_ascii_case(filename.to_bytes_with_nul()));
            assert!(mode.eq_ignore_ascii_case(c"octet".to_bytes_with_nul()))
        }

        #[test]
        fn test_new_netascii() {
            let filename = c"foo_bar.txt";
            let mut tx = TX;

            let (result, tx_len) =
                download::new(&mut tx, filename, Mode::Netascii).unwrap();
            assert_eq!(result, AwaitingData { block_no: 1 });

            let tx = &tx[..tx_len];
            let (opcode, rest) = tx.split_at(2);
            assert_eq!(opcode, 1u16.to_be_bytes());
            let (filename_bytes, mode) =
                rest.split_at(rest.iter().position(|char| *char == b'\0').unwrap() + 1);
            assert!(filename_bytes.eq_ignore_ascii_case(filename.to_bytes_with_nul()));
            assert!(mode.eq_ignore_ascii_case(c"netascii".to_bytes_with_nul()))
        }

        #[test]
        fn test_new_long_filename() {
            let filename = &concat_arrays!([0; u8] => [b'a'; PACKET_SIZE - 1], [b'\0']);

            let filename = CStr::from_bytes_with_nul(filename).unwrap();

            let mut tx = [0u8; PACKET_SIZE];
            let result = download::new(&mut tx, filename, Mode::Octect);
            assert!(matches!(
                result,
                Err(FilenameError {
                    kind: FilenameErrorKind::TooLong(_),
                    ..
                })
            ))
        }

        #[test]
        fn test_process_intermediate_block() {
            let mut tx = TX;
            const AWAITING: AwaitingData = AwaitingData { block_no: 1234 };

            let packet = concat_arrays!([0; u8] =>
                u16::to_be_bytes(3), u16::to_be_bytes(1234),
                array_slice!(LOREM_BYTES; 0, BLOCK_SIZE)
            );

            let (result, tx_len) = AWAITING.process(&packet, &mut tx);

            assert_eq!(
                result,
                Ok(BlockReceived::Intermediate(
                    AwaitingData {
                        block_no: AWAITING.block_no.wrapping_add(1)
                    },
                    &array_slice!(LOREM_BYTES; 0, BLOCK_SIZE)
                ))
            );

            let tx_len = tx_len.unwrap();
            let ack =
                concat_arrays!([0; u8] => u16::to_be_bytes(4), u16::to_be_bytes(1234));
            assert_eq!(&tx[..tx_len], ack);
        }

        #[test]
        fn test_process_final_block() {
            let mut tx = TX;
            const AWAITING: AwaitingData = AwaitingData { block_no: 1234 };

            let packet = concat_arrays!([0; u8] =>
                u16::to_be_bytes(3), u16::to_be_bytes(1234),
                array_slice!(LOREM_BYTES; 0, BLOCK_SIZE - 1)
            );

            let (result, tx_len) = AWAITING.process(&packet, &mut tx);

            assert_eq!(
                result,
                Ok(BlockReceived::Final(&LOREM_BYTES[..BLOCK_SIZE - 1]))
            );

            let tx_len = tx_len.unwrap();
            let ack =
                concat_arrays!([0; u8] => u16::to_be_bytes(4), u16::to_be_bytes(1234));
            assert_eq!(&tx[..tx_len], ack);
        }

        #[test]
        fn test_process_retransmission() {
            macro_rules! packet_with_block_no {
                ($block_no:expr) => {
                    concat_arrays!([0; u8] =>
                        u16::to_be_bytes(3), u16::to_be_bytes($block_no),
                        array_slice!(LOREM_BYTES; 0, BLOCK_SIZE - 1), [0]
                    )
                }
            }

            let mut tx = TX;
            const AWAITING: AwaitingData = AwaitingData { block_no: 1234 };

            assert!(matches!(
                AWAITING.process(&packet_with_block_no!(0u16), &mut tx),
                (Ok(BlockReceived::Retransmission(AWAITING)), None)
            ));
            assert!(matches!(
                AWAITING.process(&packet_with_block_no!(2345u16), &mut tx),
                (Ok(BlockReceived::Retransmission(AWAITING)), None)
            ));
            assert!(matches!(
                AWAITING.process(&packet_with_block_no!(56789u16), &mut tx),
                (Ok(BlockReceived::Retransmission(AWAITING)), None)
            ));
        }

        #[test]
        fn test_process_bad_opcode() {
            macro_rules! packet {
                ($opcode: expr, $block_no:expr) => {
                    concat_arrays!([0; u8] =>
                        u16::to_be_bytes($opcode), u16::to_be_bytes($block_no),
                        array_slice!(LOREM_BYTES; 0, BLOCK_SIZE - 1), [0]
                    )
                }
            }

            macro_rules! with_opcode {
                ($opcode: expr, $awaiting: expr, $tx: expr) => {{
                    const OPCODE: u16 = $opcode;
                    let packet = &packet!(OPCODE, 1234);
                    let (result, tx_len) = $awaiting.process(packet, $tx);
                    assert_eq!(result, Err(TransferError::BadPacket));
                    tx_len
                        .inspect(|tx_len| assert_is_err(&$tx[..*tx_len], Some(4), None));
                }};
            }

            let mut tx = TX;
            const AWAITING: AwaitingData = AwaitingData { block_no: 1234 };

            with_opcode!(0, AWAITING, &mut tx);
            with_opcode!(1, AWAITING, &mut tx);
            with_opcode!(2, AWAITING, &mut tx);
            with_opcode!(4, AWAITING, &mut tx);
            with_opcode!(5, AWAITING, &mut tx);
            with_opcode!(6, AWAITING, &mut tx);
            with_opcode!(12345, AWAITING, &mut tx);
            with_opcode!(56789, AWAITING, &mut tx);

            let packet = &concat_arrays!([0; u8] => u16::to_be_bytes(4), u16::to_be_bytes(AWAITING.block_no));
            let (result, tx_len) = AWAITING.process(packet, &mut tx);
            assert_eq!(result, Err(TransferError::BadPacket));
            tx_len.inspect(|tx_len| assert_is_err(&tx[..*tx_len], Some(4), None));
        }

        #[test]
        fn test_process_trailing_garbage() {
            let mut tx = TX;
            let awaiting = AwaitingData { block_no: 1234 };

            let packet = &concat_arrays!([0; u8] =>
                u16::to_be_bytes(4), u16::to_be_bytes(1234), [0, 1, 2, 3, 4, 5, 6]
            );

            let (result, tx_len) = awaiting.process(packet, &mut tx);
            assert_eq!(result, Err(TransferError::BadPacket));
            tx_len.inspect(|tx_len| assert_is_err(&tx[..*tx_len], Some(0), None));
        }

        #[test]
        fn test_process_block_too_long() {
            let mut tx = TX;
            let awaiting = AwaitingData { block_no: 1234 };

            let packet = &concat_arrays!([0; u8] => u16::to_be_bytes(3), u16::to_be_bytes(1234), LOREM_BYTES);

            let (result, tx_len) = awaiting.process(packet, &mut tx);
            assert_eq!(result, Err(TransferError::BadPacket));
            tx_len.inspect(|tx_len| assert_is_err(&tx[..*tx_len], Some(0), None));
        }

        #[test]
        fn test_process_peer_error() {
            macro_rules! packet {
                ($error_code: expr, $error_message:expr) => {
                    concat_arrays!([0; u8] =>
                        u16::to_be_bytes(5), u16::to_be_bytes($error_code), $error_message
                    )
                }
            }

            macro_rules! with_error {
                ($error:expr, $error_code: expr, $error_message: expr, $awaiting: expr, $tx: expr) => {{
                    const ERROR_CODE: u16 = $error_code;
                    let packet = &packet!(ERROR_CODE, $error_message);
                    let (result, tx_len) = $awaiting.process(packet, $tx);
                    assert_eq!(
                        result,
                        Err(TransferError::Peer(PeerError {
                            code: $error,
                            message: CStr::from_bytes_with_nul($error_message).unwrap()
                        }))
                    );
                    assert_eq!(tx_len, None);
                }};
            }

            let mut tx = TX;
            let awaiting = AwaitingData { block_no: 1234 };

            const MESSAGE: &[u8] = b"lorem ipsum dolor sit amet\0";

            with_error!(ErrorCode::Undefined, 0, MESSAGE, awaiting, &mut tx);
            with_error!(ErrorCode::FileNotFound, 1, MESSAGE, awaiting, &mut tx);
            with_error!(ErrorCode::AccessViolation, 2, MESSAGE, awaiting, &mut tx);
            with_error!(ErrorCode::DiskFull, 3, MESSAGE, awaiting, &mut tx);
            with_error!(ErrorCode::IllegalOperation, 4, MESSAGE, awaiting, &mut tx);
            with_error!(ErrorCode::UnknownTransferID, 5, MESSAGE, awaiting, &mut tx);
            with_error!(ErrorCode::FileAlreadyExists, 6, MESSAGE, awaiting, &mut tx);
            with_error!(ErrorCode::NoSuchUser, 7, MESSAGE, awaiting, &mut tx);
        }

        #[test]
        fn test_process_unterminated_peer_error() {
            let mut tx = TX;
            let awaiting = AwaitingData { block_no: 1234 };

            let packet = &concat_arrays!([0; u8] =>
                u16::to_be_bytes(5), u16::to_be_bytes(ErrorCode::Undefined as u16),
                b"lorem ipsum dolor sit amet"
            );

            let (result, tx_len) = awaiting.process(packet, &mut tx);

            assert_eq!(result, Err(TransferError::BadPacket));
            tx_len.inspect(|tx_len| assert_is_err(&tx[..*tx_len], Some(0), None));
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
    #[derive(Hash)]
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
                | _ => {
                    return bad_packet(
                        ErrorCode::IllegalOperation,
                        c"illegal operation",
                        tx,
                    )
                }
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
    #[derive(Clone, Copy)]
    #[derive(Eq, PartialEq)]
    #[derive(Hash)]
    pub enum AckReceived {
        NextBlock(AwaitingAck),
        TransferComplete,
        Retransmission(AwaitingAck),
    }

    #[cfg(test)]
    mod tests {
        use macro_rules_attribute::apply;

        use crate::concat_arrays;
        use crate::infer_array_size;
        use crate::test_helpers::*;

        use super::*;

        #[apply(infer_array_size)]
        const LOREM_BYTES: [u8; _] = *include_bytes!("lorem.txt");
        const TX: [u8; PACKET_SIZE] = [0; PACKET_SIZE];

        #[test]
        fn test_new_octet() {
            let filename = c"foo_bar.txt";
            let mut tx = TX;

            let (result, tx_len) = upload::new(&mut tx, filename, Mode::Octect).unwrap();
            assert_eq!(result, AwaitingAck { block_no: 0 });

            let tx = &tx[..tx_len];
            let (opcode, rest) = tx.split_at(2);
            assert_eq!(opcode, 2u16.to_be_bytes());
            let (filename_bytes, mode) =
                rest.split_at(rest.iter().position(|char| *char == b'\0').unwrap() + 1);
            assert!(filename_bytes.eq_ignore_ascii_case(filename.to_bytes_with_nul()));
            assert!(mode.eq_ignore_ascii_case(c"octet".to_bytes_with_nul()))
        }

        #[test]
        fn test_new_netascii() {
            let filename = c"foo_bar.txt";
            let mut tx = TX;

            let (result, tx_len) =
                upload::new(&mut tx, filename, Mode::Netascii).unwrap();
            assert_eq!(result, AwaitingAck { block_no: 0 });

            let tx = &tx[..tx_len];
            let (opcode, rest) = tx.split_at(2);
            assert_eq!(opcode, 2u16.to_be_bytes());
            let (filename_bytes, mode) =
                rest.split_at(rest.iter().position(|char| *char == b'\0').unwrap() + 1);
            assert!(filename_bytes.eq_ignore_ascii_case(filename.to_bytes_with_nul()));
            assert!(mode.eq_ignore_ascii_case(c"netascii".to_bytes_with_nul()))
        }

        #[test]
        fn test_new_long_filename() {
            let filename = &concat_arrays!([0; u8] => [b'a'; PACKET_SIZE - 1], [b'\0']);

            let filename = CStr::from_bytes_with_nul(filename).unwrap();

            let mut tx = [0u8; PACKET_SIZE];
            let result = upload::new(&mut tx, filename, Mode::Octect);
            assert!(matches!(
                result,
                Err(FilenameError {
                    kind: FilenameErrorKind::TooLong(_),
                    ..
                })
            ))
        }

        #[test]
        fn test_process_intermediate_block() {
            let mut tx = TX;
            const AWAITING: AwaitingAck = AwaitingAck { block_no: 1234 };

            let packet = concat_arrays!([0; u8] =>
                u16::to_be_bytes(4), u16::to_be_bytes(1234)
            );

            let mut data = LOREM_BYTES.iter().copied();
            let (result, tx_len) = AWAITING.process(&packet, &mut tx, data.by_ref());

            assert_eq!(
                result,
                Ok(AckReceived::NextBlock(AwaitingAck {
                    block_no: AWAITING.block_no.wrapping_add(1)
                }))
            );
            assert!(data.eq(LOREM_BYTES[BLOCK_SIZE..].iter().copied()));

            let tx_len = tx_len.unwrap();
            let data = concat_arrays!([0; u8] => u16::to_be_bytes(3), u16::to_be_bytes(AWAITING.block_no.wrapping_add(1)), array_slice!(LOREM_BYTES; 0, BLOCK_SIZE));
            assert_eq!(&tx[..tx_len], data);
        }

        #[test]
        fn test_process_final_block() {
            let mut tx = TX;
            const AWAITING: AwaitingAck = AwaitingAck { block_no: 1234 };

            let packet = concat_arrays!([0; u8] =>
                u16::to_be_bytes(4), u16::to_be_bytes(1234)
            );

            let mut data = LOREM_BYTES[..BLOCK_SIZE - 1].iter().copied();
            let (result, tx_len) = AWAITING.process(&packet, &mut tx, data.by_ref());

            assert_eq!(
                result,
                Ok(AckReceived::NextBlock(AwaitingAck {
                    block_no: AWAITING.block_no.wrapping_add(1)
                }))
            );
            assert!(data.eq(core::iter::empty()));

            let tx_len = tx_len.unwrap();
            let data = concat_arrays!([0; u8] => u16::to_be_bytes(3), u16::to_be_bytes(AWAITING.block_no.wrapping_add(1)), array_slice!(LOREM_BYTES; 0, BLOCK_SIZE - 1));
            assert_eq!(&tx[..tx_len], data);
        }

        #[test]
        fn test_process_transfer_complete() {
            let mut tx = TX;
            const AWAITING: AwaitingAck = AwaitingAck { block_no: 1234 };

            let packet = concat_arrays!([0; u8] =>
                u16::to_be_bytes(4), u16::to_be_bytes(1234)
            );

            let mut data = core::iter::empty();
            let (result, tx_len) = AWAITING.process(&packet, &mut tx, data.by_ref());

            assert_eq!(result, Ok(AckReceived::TransferComplete));
            assert!(data.eq(core::iter::empty()));

            assert_eq!(tx_len, None);
        }

        #[test]
        fn test_process_retransmission() {
            macro_rules! packet_with_block_no {
                ($block_no:expr) => {
                    concat_arrays!([0; u8] =>
                        u16::to_be_bytes(4), u16::to_be_bytes($block_no)
                    )
                }
            }

            let mut tx = TX;
            const AWAITING: AwaitingAck = AwaitingAck { block_no: 1234 };

            assert!(matches!(
                AWAITING.process(
                    &packet_with_block_no!(0u16),
                    &mut tx,
                    core::iter::empty()
                ),
                (Ok(AckReceived::Retransmission(AWAITING)), None)
            ));
            assert!(matches!(
                AWAITING.process(
                    &packet_with_block_no!(2345u16),
                    &mut tx,
                    core::iter::empty()
                ),
                (Ok(AckReceived::Retransmission(AWAITING)), None)
            ));
            assert!(matches!(
                AWAITING.process(
                    &packet_with_block_no!(56789u16),
                    &mut tx,
                    core::iter::empty()
                ),
                (Ok(AckReceived::Retransmission(AWAITING)), None)
            ));
        }

        #[test]
        fn test_process_bad_opcode() {
            macro_rules! packet {
                ($opcode: expr, $block_no:expr) => {
                    concat_arrays!([0; u8] =>
                        u16::to_be_bytes($opcode), u16::to_be_bytes($block_no)
                    )
                }
            }

            macro_rules! with_opcode {
                ($opcode: expr, $awaiting: expr, $tx: expr) => {{
                    const OPCODE: u16 = $opcode;
                    let packet = &packet!(OPCODE, 1234);
                    let (result, tx_len) =
                        $awaiting.process(packet, $tx, core::iter::empty());
                    assert_eq!(result, Err(TransferError::BadPacket));
                    tx_len
                        .inspect(|tx_len| assert_is_err(&$tx[..*tx_len], Some(4), None));
                }};
            }

            let mut tx = TX;
            const AWAITING: AwaitingAck = AwaitingAck { block_no: 1234 };

            with_opcode!(0, AWAITING, &mut tx);
            with_opcode!(1, AWAITING, &mut tx);
            with_opcode!(2, AWAITING, &mut tx);
            with_opcode!(3, AWAITING, &mut tx);
            with_opcode!(5, AWAITING, &mut tx);
            with_opcode!(6, AWAITING, &mut tx);
            with_opcode!(12345, AWAITING, &mut tx);
            with_opcode!(56789, AWAITING, &mut tx);

            let packet = &concat_arrays!([0; u8] => u16::to_be_bytes(3), u16::to_be_bytes(AWAITING.block_no), array_slice!(LOREM_BYTES; 0, BLOCK_SIZE));
            let (result, tx_len) = AWAITING.process(packet, &mut tx, core::iter::empty());
            assert_eq!(result, Err(TransferError::BadPacket));
            tx_len.inspect(|tx_len| assert_is_err(&tx[..*tx_len], Some(4), None));
        }

        #[test]
        fn test_process_trailing_garbage() {
            let mut tx = TX;
            let awaiting = AwaitingAck { block_no: 1234 };

            let packet = &concat_arrays!([0; u8] =>
                u16::to_be_bytes(4), u16::to_be_bytes(1234), [0, 1, 2, 3, 4, 5, 6]
            );

            let (result, tx_len) = awaiting.process(packet, &mut tx, core::iter::empty());
            assert_eq!(result, Err(TransferError::BadPacket));
            assert_eq!(tx_len, None);
        }

        #[test]
        fn test_process_peer_error() {
            macro_rules! packet {
                ($error_code: expr, $error_message:expr) => {
                    concat_arrays!([0; u8] =>
                        u16::to_be_bytes(5), u16::to_be_bytes($error_code), $error_message
                    )
                }
            }

            macro_rules! with_error {
                ($error:expr, $error_code: expr, $error_message: expr, $awaiting: expr, $tx: expr) => {{
                    const ERROR_CODE: u16 = $error_code;
                    let packet = &packet!(ERROR_CODE, $error_message);
                    let (result, tx_len) =
                        $awaiting.process(packet, $tx, core::iter::empty());
                    assert_eq!(
                        result,
                        Err(TransferError::Peer(PeerError {
                            code: $error,
                            message: CStr::from_bytes_with_nul($error_message).unwrap()
                        }))
                    );
                    assert_eq!(tx_len, None);
                }};
            }

            let mut tx = TX;
            let awaiting = AwaitingAck { block_no: 1234 };

            const MESSAGE: &[u8] = b"lorem ipsum dolor sit amet\0";

            with_error!(ErrorCode::Undefined, 0, MESSAGE, awaiting, &mut tx);
            with_error!(ErrorCode::FileNotFound, 1, MESSAGE, awaiting, &mut tx);
            with_error!(ErrorCode::AccessViolation, 2, MESSAGE, awaiting, &mut tx);
            with_error!(ErrorCode::DiskFull, 3, MESSAGE, awaiting, &mut tx);
            with_error!(ErrorCode::IllegalOperation, 4, MESSAGE, awaiting, &mut tx);
            with_error!(ErrorCode::UnknownTransferID, 5, MESSAGE, awaiting, &mut tx);
            with_error!(ErrorCode::FileAlreadyExists, 6, MESSAGE, awaiting, &mut tx);
            with_error!(ErrorCode::NoSuchUser, 7, MESSAGE, awaiting, &mut tx);
        }

        #[test]
        fn test_process_unterminated_peer_error() {
            let mut tx = TX;
            let awaiting = AwaitingAck { block_no: 1234 };

            let packet = &concat_arrays!([0; u8] =>
                u16::to_be_bytes(5), u16::to_be_bytes(ErrorCode::Undefined as u16),
                b"lorem ipsum dolor sit amet"
            );

            let (result, tx_len) = awaiting.process(packet, &mut tx, core::iter::empty());

            assert_eq!(result, Err(TransferError::BadPacket));
            tx_len.inspect(|tx_len| assert_is_err(&tx[..*tx_len], Some(0), None));
        }
    }
}

fn bad_packet<'message, T>(
    code: ErrorCode,
    message: &'message CStr,
    tx: &mut [u8; PACKET_SIZE],
) -> (Result<T, TransferError<'message>>, Option<usize>) {
    (
        Err(TransferError::BadPacket),
        Some(must_write(
            Packet::Error(ProtocolError { code, message })
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
