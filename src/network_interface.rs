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

use crate::{Decoder, Encoder, nb};
use smoltcp::Result;
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

const MTU: usize = 1536;

struct NetworkInterface<R,W>
    where
        R: FnMut() -> nb::Result<u8,()>,
        W: FnMut(u8) -> nb::Result<(),()>,
{
    decoder: Decoder<R>,
    encoder: Encoder<W>,

    // Only save space for a single TX frame and a single RX frame at a time for now
    rx_buffer: [u8; MTU],
    tx_buffer: [u8; MTU],
}

impl<R,W> NetworkInterface<R,W>
    where
        R: FnMut() -> nb::Result<u8,()>,
        W: FnMut(u8) -> nb::Result<(),()>,
{
    pub fn new(reader: R, writer: W) -> NetworkInterface<R,W> {
        NetworkInterface {
            decoder: Decoder::new(reader, true),
            encoder: Encoder::new(writer),
            rx_buffer: [0; 1536],
            tx_buffer: [0; 1536],
        }
    }
}

impl<'a,R,W> phy::Device<'a> for NetworkInterface<R,W> 
    where
        R: FnMut() -> nb::Result<u8,()>,
        W: FnMut(u8) -> nb::Result<(),()>,
{
    type RxToken = NetworkInterfacePhyRxToken<'a>;
    type TxToken = NetworkInterfacePhyTxToken<'a>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        Some((
            NetworkInterfacePhyRxToken(&mut self.rx_buffer[..]),
            NetworkInterfacePhyRxToken(&mut self.tx_buffer[..])
        ))
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(NetworkInterfacePhyRxToken(&mut self.tx_buffer[..]))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = MTU;
        caps.max_burst_size = Some(1);
        caps.medium = Medium::Ethernet;
        caps
    }
}

struct NetworkInterfacePhyRxToken<'a>(&'a mut [u8]);

impl<'a> phy::RxToken for NetworkInterfacePhyRxToken<'a> {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> Result<R>
        where F: FnOnce(&mut [u8]) -> Result<R>
    {
        // TODO: receive packet into buffer
        let result = f(&mut self.0);
        result
    }
}

struct NetworkInterfacePhyTxToken<'a>(&'a mut [u8]);

impl<'a> phy::TxToken for NetworkInterfacePhyTxToken<'a> {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> Result<R>
        where F: FnOnce(&mut [u8]) -> Result<R>
    {
        let result = f(&mut self.0[..len]);
        // TODO: send packet out
        result
    }
}
