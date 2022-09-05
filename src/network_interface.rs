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

#[cfg(feature = "network-interface")]
{

    use smoltcp::Result;
    use smoltcp::phy::{self, DeviceCapabilities, Device, Medium};
    use smoltcp::time::Instant;

    struct<'a> NetworkInterface {
        // tx and rx buffers
    }

    impl<'a> phy::Device<'a> for NetworkInterface {
        type RxToken = ;
        type TxToken = ;

        fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
            // ... receive logic ...
        }

        fn transmit(&'a mut self) -> Option<Self::TxToken> {
            // ... transmit logic ...
        }

        fn capabilities(&self) -> DeviceCapabilities {
            let mut caps = DeviceCapabilities::default();
            caps.max_transmission_unit = ;
            caps.max_burst_size = ;
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
}
