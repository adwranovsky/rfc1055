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

use crate::{
    Decoder,
    Encoder,
    nb,
};
use smoltcp;
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

const MTU: usize = 1536;

enum RxState {
    Reading(usize),
    Ready(usize),
}

enum TxState {
    Idle,
    Writing(usize,usize), // (num_written, frame_length)
}

/// A [smoltcp] PHY consisting an [crate::Decoder] and [crate::Encoder]. Currently only
/// supports a burst size of 1 and an MTU of 1536.
pub struct NetworkInterface<R,W>
    where
        R: FnMut() -> nb::Result<u8,()>,
        W: FnMut(u8) -> nb::Result<(),()>,
{
    decoder: Decoder<R>,
    encoder: Encoder<W>,

    // Only save space for a single TX frame and a single RX frame at a time for now
    rx_state: RxState,
    rx_buffer: [u8; MTU],
    tx_state: TxState,
    tx_buffer: [u8; MTU],
}

impl<R,W> NetworkInterface<R,W>
    where
        R: FnMut() -> nb::Result<u8,()>,
        W: FnMut(u8) -> nb::Result<(),()>,
{
    /// Creates a network interface from the given reader and writer. See [crate::Decoder::new]
    /// and [crate::Encoder::new] for descriptions on the `reader` and `writer` arguments.
    pub fn new(reader: R, writer: W) -> NetworkInterface<R,W> {
        NetworkInterface {
            decoder: Decoder::new(reader, true),
            encoder: Encoder::new(writer),

            rx_state: RxState::Reading(0),
            rx_buffer: [0; 1536],

            tx_state: TxState::Idle,
            tx_buffer: [0; 1536],
        }
    }
}

impl<'a,R,W> phy::Device<'a> for NetworkInterface<R,W> 
    where
        R: FnMut() -> nb::Result<u8,()> + 'a,
        W: FnMut(u8) -> nb::Result<(),()> + 'a,
{
    type RxToken = RxToken<'a>;
    type TxToken = TxToken<'a>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        // Try to read more data
        if let RxState::Reading(total_read) = self.rx_state {
            match self.decoder.read(&mut self.rx_buffer[total_read..]) {
                Err(nb::Error::WouldBlock) => {
                    return None;
                },
                Err(nb::Error::Other(_)) => {
                    // Reset the RX interface on error
                    self.rx_state = RxState::Reading(0);
                    return None;
                },
                Ok(0) => {
                    // `read` returns 0 to indicate the end of a frame
                    self.rx_state = RxState::Ready(total_read);
                },
                Ok(n) => {
                    // We read a partial frame so return `None`
                    self.rx_state = RxState::Reading(total_read+n);
                    return None;
                },
            }
        }

        // Return rx and tx tokens if both interfaces are ready
        let num_rx = if let (RxState::Ready(num_rx), TxState::Idle) = (&self.rx_state, &self.tx_state) {
            *num_rx
        } else {
            return None;
        };

        Some((
            RxToken (
                &mut self.rx_buffer[..num_rx],
                &mut self.rx_state,
            ),
            TxToken (
                &mut self.tx_buffer[..],
                &mut self.tx_state,
            ),
        ))
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        // Write data if we're holding onto a frame
        if let TxState::Writing(total_written, frame_length) = self.tx_state {
            match self.encoder.write(&self.tx_buffer[total_written..frame_length]) {
                Err(nb::Error::WouldBlock) => {
                    return None;
                },
                Err(nb::Error::Other(_)) => {
                    // Reset the TX interface on error and return the frame back to the application
                    self.tx_state = TxState::Idle;
                    Some(
                        TxToken (
                            &mut self.tx_buffer[..],
                            &mut self.tx_state,
                        )
                    )
                },
                Ok(n) => {
                    if total_written+n == frame_length {
                        // We finished writing the frame so return the buffer back up to the
                        // application
                        Some(
                            TxToken (
                                &mut self.tx_buffer[..],
                                &mut self.tx_state,
                            )
                        )
                    } else {
                        self.tx_state = TxState::Writing(total_written+n, frame_length);
                        None
                    }
                },
            }
        } else {
            Some(
                TxToken (
                    &mut self.tx_buffer[..],
                    &mut self.tx_state,
                )
            )
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = MTU;
        caps.max_burst_size = Some(1);
        caps.medium = Medium::Ethernet;
        caps
    }
}

pub struct RxToken<'a>(&'a mut [u8], &'a mut RxState);
pub struct TxToken<'a>(&'a mut [u8], &'a mut TxState);

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

impl<'a> phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
        where F: FnOnce(&mut [u8]) -> smoltcp::Result<R>
    {
        // Fetch the next frame and transition to the writing state
        let result = f(&mut self.0[..len]);
        *self.1 = TxState::Writing(0,len);
        result
    }
}
