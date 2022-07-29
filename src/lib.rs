//#![deny(missing_docs)]
#![deny(warnings)]
#![no_std]

// https://datatracker.ietf.org/doc/html/rfc1055

pub use nb;

pub const END: u8 = 0o300;
pub const ESC: u8 = 0o333;
pub const ESC_END: u8 = 0o334;
pub const ESC_ESC: u8 = 0o335;

#[derive(PartialEq)]
#[derive(Debug)]
pub enum DecodeError {
    BadEscape,
    ReadError,
}

enum DecoderState {
    DiscardToEnd,
    WriteToBuf,
    Escape,
    End,
}

pub struct Decoder<T>
    where T: FnMut() -> nb::Result<u8,()>
{
    state: DecoderState,
    reader: T,
}

impl<T> Decoder<T>
    where T: FnMut() -> nb::Result<u8,()>
{
    pub fn new(reader: T) -> Decoder<T> {
        Decoder {
            state: DecoderState::DiscardToEnd,
            reader: reader,
        }
    }

    ///
    /// Reads from the decoder into the given buffer. It mirrors the `std::io::Read::read` function
    /// as closely as possible while adding support for `no_std` and the non-blocking crate.
    ///
    ///
    /// # Arguments
    ///
    /// * `buf` - A u8 slice to write the decoded data into
    ///
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rfc1055::{
    ///     END,
    ///     ESC,
    ///     ESC_END,
    ///     ESC_ESC,
    /// };
    /// fn main() {
    ///     let data_stream: [u8; 11] = [END, 0xaa, 0xbb, 0xcc, ESC, ESC_END, ESC, ESC_ESC, 0xdd, 0xee, END];
    ///     let mut decoder = rfc1055::decode_from_buffer(&data_stream[..]);
    ///     let mut packet: [u8; 7] = [0; 7];
    ///
    ///     let read_result = decoder.read(&mut packet[..]);
    ///     assert_eq!(read_result, Ok(7));
    ///     assert_eq!(packet, [0xaa, 0xbb, 0xcc, END, ESC, 0xdd, 0xee]);
    /// }
    /// ```
    ///
    pub fn read(&mut self, buf: &mut [u8]) -> nb::Result<usize, DecodeError> {
        let mut num_written: usize = 0;

        // Signal end-of-frame if needed
        if let DecoderState::End = self.state {
            self.state = DecoderState::WriteToBuf;
            return Ok(0);
        }

        // Discard bytes until we reach the end of the frame. This is done following either decoder
        // creation or an invalid escape sequence.
        if let DecoderState::DiscardToEnd = self.state {
            loop {
                match (self.reader)() {
                    Ok(END)                    => {self.state = DecoderState::WriteToBuf; break;},
                    Ok(_)                      => {},
                    Err(nb::Error::WouldBlock) => return Err(nb::Error::WouldBlock),
                    Err(nb::Error::Other(_))   => return Err(nb::Error::Other(DecodeError::ReadError)),
                }
            }
        }

        // Decode bytes and write to the buffer until we either fill the buffer, need to block on
        // more input being available, or reach the end of the frame
        for item in buf.iter_mut() {
            // Loop until we find a valid character sequence
            loop {
                // Read the next character, blocking if needed
                let value = match (self.reader)() {
                    Err(nb::Error::WouldBlock) => {
                        if num_written == 0 {
                            return Err(nb::Error::WouldBlock);
                        } else {
                            return Ok(num_written);
                        }
                    },
                    Err(nb::Error::Other(_)) => {
                        self.state = DecoderState::DiscardToEnd;
                        return Err(nb::Error::Other(DecodeError::ReadError));
                    },
                    Ok(value) => value,
                };

                // What we do with the character depends on what state we're in
                match self.state {
                    // Write the value to the current position in the buffer and then move on
                    DecoderState::WriteToBuf => {
                        match value {
                            END => {
                                self.state = DecoderState::End;
                                return Ok(num_written);
                            },
                            ESC => {
                                self.state = DecoderState::Escape;
                            },
                            value => {
                                num_written += 1;
                                *item = value;
                                break;
                            },
                        };
                    },

                    // Write the escaped character to the current position in the buffer if it's
                    // valid, otherwise bail on decoding this frame
                    DecoderState::Escape => {
                        num_written += 1;
                        *item = match value {
                            ESC_END => {
                                self.state = DecoderState::WriteToBuf;
                                END
                            },
                            ESC_ESC => {
                                self.state = DecoderState::WriteToBuf;
                                ESC
                            },
                            _ => {
                                self.state = DecoderState::DiscardToEnd;
                                return Err(nb::Error::Other(DecodeError::BadEscape));
                            }
                        };
                        break;
                    }

                    // All other states should be unreachable, so panic upon hitting them
                    _ => panic!("The Decoder is in an invalid state!"),
                }
            }
        }

        Ok(num_written)
    }
}

pub fn decode_from_buffer(buffer: &[u8]) -> Decoder<impl FnMut() -> nb::Result<u8,()> + '_> {
    let mut buffer_iterator = buffer.iter();
    let reader = move || {
        match buffer_iterator.next() {
            Some(value) => Ok(*value),
            None => Err(nb::Error::Other(())),
        }
    };

    Decoder::new(reader)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_u8_slice() {
        let data_stream: [u8; 11] = [END, 0x00, 0x11, 0x22, ESC, ESC_END, ESC, ESC_ESC, 0x33, 0x44, END];
        let mut decoder = decode_from_buffer(&data_stream[..]);

        let mut packet: [u8; 128] = [0; 128];
        let read_result = decoder.read(&mut packet[..]);
        assert_eq!(read_result, Ok(7));
        assert_eq!(packet[0..7], [0x00, 0x11, 0x22, END, ESC, 0x33, 0x44]);
    }

    #[test]
    fn test_decode_errors() {
        let data_stream: [u8; 4] = [END, ESC, 0x00, END];
        let mut packet: [u8; 128] = [0; 128];

        let mut decoder = decode_from_buffer(&data_stream[..]);
        let read_result = decoder.read(&mut packet[..]);
        assert_eq!(read_result, Err(nb::Error::Other(DecodeError::BadEscape)));

        let mut decoder = Decoder::new(|| {Err(nb::Error::Other(()))});
        let read_result = decoder.read(&mut packet[..]);
        assert_eq!(read_result, Err(nb::Error::Other(DecodeError::ReadError)));
    }
}
