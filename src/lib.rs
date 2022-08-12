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
    WriteOneSpecial(u8),
    WriteTwoSpecial((u8,u8)),
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

        self.state = EncoderState::WriteOneSpecial(second);
        self.write_one(second)?;
        self.state = EncoderState::WriteNext;

        Ok(())
    }

    fn write_three(&mut self, first: u8, second: u8, third: u8) -> nb::Result<(), EncodeError> {
        match (self.writer)(first) {
            Ok(_) => {},
            Err(nb::Error::WouldBlock) => {return Err(nb::Error::WouldBlock);},
            Err(nb::Error::Other(_)) => {return Err(nb::Error::Other(EncodeError::WriteError));},
        }

        self.state = EncoderState::WriteTwoSpecial((second, third));
        self.write_two(second, third)?;
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
    ///           call, so the application must call `write` until the total number of bytes
    ///           written equals the length of `buf`.
    ///
    ///
    /// # Results
    ///
    /// * `nb::Result::Err(nb::Error::WouldBlock)` is returned if the underlying writer would block
    ///   and a complete character hasn't been written yet. Note that this does not mean nothing
    ///   was written, since some characters need to be escaped and the last character needs to be
    ///   followed by END.
    /// * `nb::Result::Err(nb::Error::Other(rfc1055::EncodeError::WriteError))` is returned if the
    ///   underlying writer had an error. The application should abort writing the frame in this
    ///   instance.
    /// * `nb::Result::Err(nb::Error::Other(rfc1055::EncodeError::BufferChanged))` is returned if
    ///   the encoder detects that the u8 slice wasn't updated correctly after the last command.
    ///   If this is returned there is a bug in the calling application.
    /// * `nb::Result::Ok(usize)` is returned if at least one full character was written, including
    ///   any escape or end characters. It will never exceed the length of `buf`.
    ///
    ///
    pub fn write(&mut self, buf: &[u8]) -> nb::Result<usize, EncodeError> {

        // If an empty buffer is passed in, just write the END symbol
        if buf.len() == 0 {
            self.write_one(END)?;
            return Ok(0);
        }

        let mut num_written = 0;
        for i in 0..buf.len()-1 {
            // Write out the item in the buffer. Some values will require up to two writes.
            let write_result = match self.state {
                EncoderState::WriteNext => {
                    match buf[i] {
                        ESC => {self.write_two(ESC, ESC_ESC)},
                        END => {self.write_two(ESC, ESC_END)},
                        other => {self.write_one(other)},
                    }
                },
                EncoderState::WriteOneSpecial(val) => {
                    self.write_one(val)
                },
                EncoderState::WriteTwoSpecial(_) => {
                    // This state is only possible if the application swapped out the buffer before
                    // fully encoding it, or didn't correctly update the slice after a partial
                    // write
                    self.state = EncoderState::WriteNext;
                    return Err(nb::Error::Other(EncodeError::BufferChanged));
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

        // Write the last character along with any escape sequences and the end-of-frame symbol
        let write_result = match self.state {
            EncoderState::WriteNext => {
                match buf[buf.len()-1] {
                    ESC => {self.write_three(ESC, ESC_ESC, END)},
                    END => {self.write_three(ESC, ESC_END, END)},
                    other => {self.write_two(other, END)},
                }
            },
            EncoderState::WriteOneSpecial(val) => {
                self.write_one(val)
            },
            EncoderState::WriteTwoSpecial((val1,val2)) => {
                self.write_two(val1, val2)
            },
        };

        match write_result {
            Ok(()) => {
                self.state = EncoderState::WriteNext;
                Ok(num_written + 1)
            },
            Err(nb::Error::WouldBlock) => {
                if num_written > 0 {
                    Ok(num_written)
                } else {
                    Err(nb::Error::WouldBlock)
                }
            },
            Err(other_err_type) => {
                Err(other_err_type)
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
    use nb::block;

    //
    // Decoder tests
    //

    fn decode_blocking(input: &[u8], output: &mut [u8]) -> Result<usize, DecodeError> {
        let mut decoder = {
            let mut buffer_iterator = input.iter();
            let mut block: bool = false;
            let reader = move || {
                block = !block;
                if block {
                    return Err(nb::Error::WouldBlock);
                }
                match buffer_iterator.next() {
                    Some(x) => { return Ok(*x); },
                    None => { return Err(nb::Error::Other(())); },
                }
            };
            Decoder::new(reader)
        };

        let mut num_read = 0;
        loop {
            match block!(decoder.read(&mut output[num_read..]))? {
                0 => { return Ok(num_read); },
                x => { num_read += x; },
            }
        }
    }

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
    fn test_decode_blocking() {
        let mut output: [u8; 128] = [0; 128];

        let input: [u8; 12] = [END, 0x00, 0x11, 0x22, ESC, ESC_ESC, 0x33, ESC, ESC_END, 0x44, 0x55, END];
        assert_eq!(decode_blocking(&input[..], &mut output[..]), Ok(8));
        assert_eq!(output[0..8], [0x00, 0x11, 0x22, ESC, 0x33, END, 0x44, 0x55]);

        let input: [u8; 6] = [END, ESC, ESC_END, ESC, ESC_END, END];
        assert_eq!(decode_blocking(&input[..], &mut output[..]), Ok(2));
        assert_eq!(output[0..2], [END, END]);

        let input: [u8; 4] = [END, ESC, ESC_ESC, END];
        assert_eq!(decode_blocking(&input[..], &mut output[..]), Ok(1));
        assert_eq!(output[0..1], [ESC]);
    }


    //
    // Encoder tests
    //

    fn encode(input: &[u8], output: &mut [u8]) -> Result<(), EncodeError> {
        let mut encoder = encode_to_buffer(&mut output[..]);

        let mut num_written = 0;
        loop {
            num_written += block!(encoder.write(&input[num_written..]))?;

            if num_written == input.len() {
                return Ok(());
            }
        }
    }

    fn encode_blocking(input: &[u8], output: &mut [u8]) -> Result<(), EncodeError> {
        let mut encoder = {
            // Make an encoder that blocks on every other write, starting with the first one
            let mut buffer_iterator = output.iter_mut();
            let mut block: bool = false;
            let writer = move |val| {
                block = !block;
                if block {
                    return Err(nb::Error::WouldBlock);
                }
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
        };

        let mut num_written = 0;
        loop {
            num_written += block!(encoder.write(&input[num_written..]))?;

            if num_written == input.len() {
                return Ok(());
            }
        }
    }

    #[test]
    fn test_encode_u8_slice() {
        let mut output: [u8; 128] = [0; 128];

        let input: [u8; 8] = [0x00, 0x11, 0x22, ESC, 0x33, END, 0x44, 0x55];
        assert_eq!(encode(&input[..], &mut output[..]), Ok(()));
        assert_eq!(output[0..11], [0x00, 0x11, 0x22, ESC, ESC_ESC, 0x33, ESC, ESC_END, 0x44, 0x55, END]);

        let input: [u8; 0] = [];
        assert_eq!(encode(&input[..], &mut output[..]), Ok(()));
        assert_eq!(output[0], END);

        let input: [u8; 2] = [END, END];
        assert_eq!(encode(&input[..], &mut output[..]), Ok(()));
        assert_eq!(output[0..5], [ESC, ESC_END, ESC, ESC_END, END]);

        let input: [u8; 1] = [ESC];
        assert_eq!(encode(&input[..], &mut output[..]), Ok(()));
        assert_eq!(output[0..3], [ESC, ESC_ESC, END]);
    }

    #[test]
    fn test_encode_errors() {
        let input_data: [u8; 1] = [0x00];
        let write_result = {
            let mut encoder = Encoder::new(|_| Err(nb::Error::Other(())));
            encoder.write(&input_data[..])
        };
        assert_eq!(write_result, Err(nb::Error::Other(EncodeError::WriteError)));
    }

    #[test]
    fn test_encode_blocking() {
        let mut output: [u8; 128] = [0; 128];

        let input: [u8; 8] = [0x00, 0x11, 0x22, ESC, 0x33, END, 0x44, 0x55];
        assert_eq!(encode_blocking(&input[..], &mut output[..]), Ok(()));
        assert_eq!(output[0..11], [0x00, 0x11, 0x22, ESC, ESC_ESC, 0x33, ESC, ESC_END, 0x44, 0x55, END]);

        let input: [u8; 0] = [];
        assert_eq!(encode_blocking(&input[..], &mut output[..]), Ok(()));
        assert_eq!(output[0], END);

        let input: [u8; 2] = [END, END];
        assert_eq!(encode_blocking(&input[..], &mut output[..]), Ok(()));
        assert_eq!(output[0..5], [ESC, ESC_END, ESC, ESC_END, END]);

        let input: [u8; 1] = [ESC];
        assert_eq!(encode_blocking(&input[..], &mut output[..]), Ok(()));
        assert_eq!(output[0..3], [ESC, ESC_ESC, END]);
    }
}
