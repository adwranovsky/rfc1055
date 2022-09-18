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
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

enum RxState {
    Reading(usize),
    Ready(usize),
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
    tx_buffer: &'a mut [u8],
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

            tx_buffer: tx_buffer,
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
}

impl<'a,R,W> phy::Device<'a> for NetworkInterface<'_,R,W> 
    where
        R: FnMut() -> nb::Result<u8,()> + 'a,
        W: FnMut(u8) -> nb::Result<(),()> + 'a,
{
    type RxToken = RxToken<'a>;
    type TxToken = TxToken<'a, W>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        // Poll the connected device for data by sending an end-of-frame character
        match self.send_eof() {
            _ => {},
        }

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
        if let RxState::Ready(num_rx) = &self.rx_state {
            return Some((
                RxToken (
                    &mut self.rx_buffer[..*num_rx],
                    &mut self.rx_state,
                ),
                TxToken {
                    buffer: &mut self.tx_buffer[..],
                    encoder: &mut self.encoder,
                },
            ))
        } else {
            return None;
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(
            TxToken {
                buffer: &mut self.tx_buffer[..],
                encoder: &mut self.encoder,
            },
        )
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = min(self.tx_buffer.len(), self.rx_buffer.len());
        caps.max_burst_size = Some(1);
        caps.medium = Medium::Ethernet;
        caps
    }
}

pub struct RxToken<'a>(&'a mut [u8], &'a mut RxState);
pub struct TxToken<'a, T> 
    where T: FnMut(u8) -> nb::Result<(),()>
{
    buffer: &'a mut [u8],
    encoder: &'a mut Encoder<T>,
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
        // Fetch the next frame and then write it out
        let result = f(&mut self.buffer[..len]);
        let mut num_written = 0;
        loop {
            num_written += match block!(self.encoder.write(&self.buffer[num_written..len])) {
                Ok(n) => n,
                Err(_) => { break; },
            };

            if num_written == len {
                break;
            }
        }
        result
    }
}
