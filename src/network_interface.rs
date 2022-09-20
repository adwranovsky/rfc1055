/*
 * Copyright 2022 Alexander D Wranovsky
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*!

The `network_interface` module provides a way to send TCP/IP data with smoltcp over an RFC1055 encoder/decoder.

*/

use core::cmp::min;
use crate::{
    Decoder,
    Encoder,
    EncodeError,
    nb,
    nb::block,
};
use smoltcp;
use smoltcp::phy::{self, DeviceCapabilities, ChecksumCapabilities, Medium};
use smoltcp::time::Instant;
use crc::{Crc, CRC_32_BZIP2};

macro_rules! inc_saturating {
    ( $x:expr ) => {
        $x = $x.saturating_add(1);
    };
}

const FCS: Crc<u32> = Crc::<u32>::new(&CRC_32_BZIP2);
const HEADER_LENGTH: usize = 14;
const FCS_LENGTH: usize = 4;

enum RxState {
    Reading(usize),
    Ready(usize),
}

enum TxState {
    ClearToSend,
    Wait,
}

/// Stores various device statistics
pub struct DeviceStatistics {
    /// The number of complete RX frames received, regardless of CRC errors
    pub rx_frames: u64,
    /// The number of times that the decoder returned an error while reading
    pub rx_read_errors: u64,
    /// The number of RX frames that failed the CRC check
    pub rx_crc_errors: u64,
    /// The number of complete TX frames sent, regardless of TX errors
    pub tx_frames: u64,
    /// The number of times that the encoder returned an error while writing
    pub tx_write_errors: u64,
}

/// A [smoltcp] PHY consisting an [crate::Decoder] and [crate::Encoder]. Currently only
/// supports a burst size of 1.
pub struct NetworkInterface<'a,R,W>
    where
        R: FnMut() -> nb::Result<u8,()>,
        W: FnMut(u8) -> nb::Result<(),()>,
{
    decoder: Decoder<R>,
    encoder: Encoder<W>,

    // Only save space for a single TX frame and a single RX frame at a time for now
    rx_state: RxState,
    rx_buffer: &'a mut [u8],
    tx_state: TxState,
    tx_buffer: &'a mut [u8],

    statistics: DeviceStatistics,
}

impl<'a,R,W> NetworkInterface<'a,R,W>
    where
        R: FnMut() -> nb::Result<u8,()>,
        W: FnMut(u8) -> nb::Result<(),()>,
{
    /// Creates a network interface from the given reader and writer. See [crate::Decoder::new]
    /// and [crate::Encoder::new] for descriptions on the `reader` and `writer` arguments. The two
    /// buffers are where incomplete packet data will be stored. `tx_buffer` and `rx_buffer` should
    /// be of the same length. If they are different, then the extra space in the longer buffer
    /// will go unused.
    pub fn new(reader: R, writer: W, tx_buffer: &'a mut [u8], rx_buffer: &'a mut [u8]) -> NetworkInterface<'a,R,W> {
        NetworkInterface {
            decoder: Decoder::new(reader, true),
            encoder: Encoder::new(writer),

            rx_state: RxState::Reading(0),
            rx_buffer: rx_buffer,

            tx_state: TxState::Wait,
            tx_buffer: tx_buffer,

            statistics: DeviceStatistics {
                rx_frames: 0,
                rx_read_errors: 0,
                rx_crc_errors: 0,
                tx_frames: 0,
                tx_write_errors: 0,
            },
        }
    }

    /// Send an end-of-frame character. This is required to poll for data on some SLIP endpoints
    /// e.g. [SatCat5](https://github.com/the-aerospace-corporation/satcat5).
    pub fn send_eof(&mut self) -> Result<(),EncodeError> {
        // If TX behavior is ever changed to non-blocking, this function cannot proceed if we're in
        // the middle of sending an actual frame
        let empty_buf = [];
        block!(self.encoder.write(&empty_buf[..]))?;
        Ok(())
    }

    /// Get the device statistics
    pub fn get_statistics(&self) -> &DeviceStatistics {
        &self.statistics
    }
}

impl<'a,R,W> phy::Device<'a> for NetworkInterface<'_,R,W> 
    where
        R: FnMut() -> nb::Result<u8,()> + 'a,
        W: FnMut(u8) -> nb::Result<(),()> + 'a,
{
    type RxToken = RxToken<'a>;
    type TxToken = TxToken<'a, W>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        // If we don't have a full frame buffered attempt to read the next one
        if let RxState::Reading(total_read) = self.rx_state {
            // If we haven't received any fragments of the next frame, poll the connected device
            // for data by sending an end-of-frame character
            if total_read == 0 {
                match self.send_eof() {
                    _ => {},
                }
            }

            // Try to read more data
            match self.decoder.read(&mut self.rx_buffer[total_read..]) {
                Err(nb::Error::WouldBlock) => {
                    return None;
                },
                Err(nb::Error::Other(_)) => {
                    // Reset the RX interface on error
                    inc_saturating!(self.statistics.rx_read_errors);
                    self.rx_state = RxState::Reading(0);
                    return None;
                },
                Ok(0) => {
                    // `read` returns 0 to indicate the end of a frame
                    self.rx_state = if total_read >= HEADER_LENGTH + FCS_LENGTH {
                        inc_saturating!(self.statistics.rx_frames);
                        // We received a full frame, so compute the checksum
                        let fcs = &self.rx_buffer[total_read-FCS_LENGTH..total_read];
                        let fcs = u32::from_be_bytes([fcs[0], fcs[1], fcs[2], fcs[3]]);
                        let rest_of_frame = &self.rx_buffer[..total_read-FCS_LENGTH];
                        if FCS.checksum(rest_of_frame) == fcs {
                            // Frame is good, so pass it up to the next layer
                            RxState::Ready(total_read - FCS_LENGTH)
                        } else {
                            // Frame is bad, so record it and move on
                            inc_saturating!(self.statistics.rx_crc_errors);
                            RxState::Reading(0)
                        }
                    } else {
                        // If the device's link partner sent a frame with 0 length, that means
                        // we're clear to send more data, so just reset the RX interface and move
                        // along. Treat frames that are shorter than HEADER_LENGTH + FCS_LENGTH the
                        // same way.
                        RxState::Reading(0)
                    };
                    // Receiving an end-of-frame always indicates that the link partner is ready to
                    // receive more data
                    self.tx_state = TxState::ClearToSend;
                },
                Ok(n) => {
                    // We read a partial frame so return `None`
                    self.rx_state = RxState::Reading(total_read+n);
                    return None;
                },
            }
        }

        // Return rx and tx tokens if both interfaces are ready
        if let (TxState::ClearToSend, RxState::Ready(num_rx)) = (&self.tx_state, &self.rx_state) {
            return Some((
                RxToken (
                    &mut self.rx_buffer[..*num_rx],
                    &mut self.rx_state,
                ),
                TxToken {
                    buffer: &mut self.tx_buffer[..],
                    encoder: &mut self.encoder,
                    tx_state: &mut self.tx_state,
                    statistics: &mut self.statistics,
                },
            ))
        } else {
            return None;
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        if let TxState::ClearToSend = self.tx_state {
            Some(
                TxToken {
                    buffer: &mut self.tx_buffer[..],
                    encoder: &mut self.encoder,
                    tx_state: &mut self.tx_state,
                    statistics: &mut self.statistics,
                },
            )
        } else {
            None
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = min(self.tx_buffer.len(), self.rx_buffer.len()) - FCS_LENGTH;
        caps.max_burst_size = Some(1);
        caps.medium = Medium::Ethernet;
        caps.checksum = ChecksumCapabilities::default();
        caps
    }
}

pub struct RxToken<'a>(&'a mut [u8], &'a mut RxState);
pub struct TxToken<'a, T> 
    where T: FnMut(u8) -> nb::Result<(),()>
{
    buffer: &'a mut [u8],
    encoder: &'a mut Encoder<T>,
    tx_state: &'a mut TxState,
    statistics: &'a mut DeviceStatistics,
}

impl<'a> phy::RxToken for RxToken<'a> {
    fn consume<R, F>(self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
        where F: FnOnce(&mut [u8]) -> smoltcp::Result<R>
    {
        // Pass the buffer up to the next layer and return the buffer to the decoder
        *self.1 = RxState::Reading(0);
        let result = f(&mut self.0[..]);
        result
    }
}

impl<'a, T> phy::TxToken for TxToken<'a, T>
    where T: FnMut(u8) -> nb::Result<(),()>
{
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
        where F: FnOnce(&mut [u8]) -> smoltcp::Result<R>
    {
        // Fetch the next frame
        let result = f(&mut self.buffer[..len]);

        // Compute checksum and append to frame
        let fcs = FCS.checksum(&self.buffer[..len]).to_be_bytes();
        self.buffer[len..FCS_LENGTH].clone_from_slice(&fcs);
        let len = len + FCS_LENGTH;

        // Send frame
        inc_saturating!(self.statistics.tx_frames);
        let mut num_written = 0;
        loop {
            num_written += match block!(self.encoder.write(&self.buffer[num_written..len])) {
                Ok(n) => n,
                Err(_) => { 
                    inc_saturating!(self.statistics.tx_write_errors);
                    break; 
                },
            };

            if num_written == len {
                break;
            }
        }
        // Wait to send another frame until the link partner requests it
        *self.tx_state = TxState::Wait;
        result
    }
}
