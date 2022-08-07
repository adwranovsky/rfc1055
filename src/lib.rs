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
    ZeroLengthBuffer,
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
    ///
    /// Create a new decoder using the provided reader.
    ///
    /// # Arguments
    ///
    /// * `reader` - A function that reads individual `u8`s from some input source that may block.
    ///
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
    /// * `buf` - A mutable u8 slice to write the decoded data into. It is not guaranteed that the
    ///           whole packet will be written in one call.
    ///
    ///
    /// # Results
    ///
    /// * `nb::Result::Err(nb::Error::WouldBlock)` is returned if there is no data to receive and
    ///   there is no other problem.
    /// * `nb::Result::Err(nb::Error::Other(rfc1055::DecodeError::ReadError))` is returned if the
    ///   underlying reader function returned an error, and indicates any data previously read for
    ///   this packet should be discarded by the caller. The caller should not rely on `buf` being
    ///   unmodified.
    /// * `nb::Result::Err(nb::Error::Other(rfc1055::DecodeError::ZeroLengthBuffer))` is returned
    ///   if the decoder is ready to read more data, but the length of `buf` is zero.
    /// * `nb::Result::Ok(num_read)` is returned if reading was successful, with `num_read`
    ///   returning the total number of bytes read. `num_read` will never exceed the length of
    ///   `buf`. A packet boundary is indicated with `num_read` equal to zero. Therefore, at least
    ///   two calls to `read()` are needed for the caller to know that a complete packet has been
    ///   read.
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

        // The decoder is ready to read more bytes, so signal an error if the buffer is empty
        if buf.len() == 0 {
            return Err(nb::Error::Other(DecodeError::ZeroLengthBuffer));
        }

        // Decode bytes and write to the buffer until we either fill the buffer, need to block on
        // more input being available, or reach the end of the frame
        let mut num_written: usize = 0;
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

#[derive(PartialEq)]
#[derive(Debug)]
pub enum EncodeError {
    BufferChanged,
    WriteError,
}

enum EncoderState {
    WriteNext,
    WriteSpecial(u8),
}

pub struct Encoder<T>
    where T: FnMut(u8) -> nb::Result<(),()>
{
    state: EncoderState,
    writer: T,
}

impl<T> Encoder<T>
    where T: FnMut(u8) -> nb::Result<(),()>
{
    pub fn new(writer: T) -> Encoder<T> {
        Encoder {
            state: EncoderState::WriteNext,
            writer: writer,
        }
    }

    fn write_one(&mut self, val: u8) -> nb::Result<(), EncodeError> {
        match (self.writer)(val) {
            Ok(_) => {Ok(())},
            Err(nb::Error::WouldBlock) => {Err(nb::Error::WouldBlock)},
            Err(nb::Error::Other(_)) => {Err(nb::Error::Other(EncodeError::WriteError))},
        }
    }

    fn write_two(&mut self, first: u8, second: u8) -> nb::Result<(), EncodeError> {
        match (self.writer)(first) {
            Ok(_) => {},
            Err(nb::Error::WouldBlock) => {return Err(nb::Error::WouldBlock);},
            Err(nb::Error::Other(_)) => {return Err(nb::Error::Other(EncodeError::WriteError));},
        }

        self.state = EncoderState::WriteSpecial(second);

        match (self.writer)(second) {
            Ok(_) => {},
            Err(nb::Error::WouldBlock) => {return Err(nb::Error::WouldBlock);},
            Err(nb::Error::Other(_)) => {return Err(nb::Error::Other(EncodeError::WriteError));},
        }

        self.state = EncoderState::WriteNext;

        Ok(())
    }

    ///
    /// Writes to the encoder from the given buffer. It mirrors the `std::io::Write::write`
    /// function as closely as possible, while adding support for `no_std` and the non-blocking
    /// crate.
    ///
    ///
    /// # Arguments
    ///
    /// * `buf` - A `u8` slice to encode. The encoder might not write out the whole slice in one
    ///    call.
    ///
    ///
    /// # Results
    ///
    ///
    pub fn write(&mut self, buf: &[u8]) -> nb::Result<usize, EncodeError> {
        let mut num_written = 0;
        for item in buf {
            // Write out the item in the buffer. Some values will require two writes.
            let write_result = match self.state {
                EncoderState::WriteNext => {
                    match *item {
                        ESC => {self.write_two(ESC, ESC_ESC)},
                        END => {self.write_two(ESC, ESC_END)},
                        other => {self.write_one(other)},
                    }
                },
                EncoderState::WriteSpecial(val) => {
                    self.write_one(val)
                },
            };

            match write_result {
                Ok(()) => {
                    self.state = EncoderState::WriteNext;
                    num_written += 1;
                },
                Err(nb::Error::WouldBlock) => {
                    if num_written > 0 {
                        return Ok(num_written);
                    } else {
                        return Err(nb::Error::WouldBlock);
                    }
                },
                Err(other_err_type) => {
                    return Err(other_err_type);
                },
            }
        }

        // Write end-of-frame
        match self.write_one(END) {
            Ok(()) => {
                Ok(num_written)
            },
            Err(nb::Error::WouldBlock) => {
                self.state = EncoderState::WriteSpecial(END); // TODO: correctly handle blocking on END character
                if num_written > 0 {
                    // Don't count the last byte until END is written
                    Ok(num_written - 1)
                } else {
                    Err(nb::Error::WouldBlock)
                }
            },
            Err(other) => {
                Err(other)
            },
        }
    }
}

pub fn encode_to_buffer(buffer: &mut [u8]) -> Encoder<impl FnMut(u8) -> nb::Result<(),()> + '_> {
    let mut buffer_iterator = buffer.iter_mut();
    let writer = move |val| {
        match buffer_iterator.next() {
            Some(next_slot) => {
                *next_slot = val;
                Ok(())
            },
            None => {
                Err(nb::Error::Other(()))
            },
        }
    };

    Encoder::new(writer)
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

    #[test]
    fn test_encode_u8_slice() {
        let input_data: [u8; 8] = [0x00, 0x11, 0x22, ESC, 0x33, END, 0x44, 0x55];
        let mut output_packet: [u8; 128] = [0; 128];
        let write_result = {
            let mut encoder = encode_to_buffer(&mut output_packet[..]);
            encoder.write(&input_data[..])
        };
        assert_eq!(write_result, Ok(input_data.len()));
        assert_eq!(output_packet[0..11], [0x00, 0x11, 0x22, ESC, ESC_ESC, 0x33, ESC, ESC_END, 0x44, 0x55, END]);
    }
}
