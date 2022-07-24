//#![deny(missing_docs)]
#![deny(warnings)]
#![no_std]

pub use nb;

const END: u8 = 0o300;
const ESC: u8 = 0o333;
const ESC_END: u8 = 0o334;
const ESC_ESC: u8 = 0o335;

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

pub struct Rfc1055Decoder<T> where
    T: Iterator<Item=u8>
{
    state: DecoderState,
    reader: T,
}

impl<T> Rfc1055Decoder<T> where
    T: Iterator<Item=u8>
{
    pub fn new(reader: T) -> Rfc1055Decoder<T> {
        Rfc1055Decoder {
            state: DecoderState::DiscardToEnd,
            reader: reader,
        }
    }

    /// Reads from the decoder into the given buffer.
    ///
    /// 
    ///
    /// # Arguments
    ///
    /// * `buf` - A u8 slice to write the decoded data into
    ///
    ///
    ///
    /// # Examples
    ///
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
                match self.reader.next() {
                    None      => return Err(nb::Error::WouldBlock),
                    Some(END) => {self.state = DecoderState::WriteToBuf; break;},
                    Some(_)   => {},
                }
            }
        }

        // Decode bytes and write to the buffer until we either fill the buffer, need to block on
        // more input being available, or reach the end of the frame
        for item in buf.iter_mut() {
            // Loop until we find a valid character sequence
            loop {
                // Read the next character, blocking if needed
                let value = match self.reader.next() {
                    None => {
                        if num_written == 0 {
                            return Err(nb::Error::WouldBlock);
                        } else {
                            return Ok(num_written);
                        }
                    },
                    Some(value) => value,
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
                    _ => panic!("The Rfc1055Decoder is in an invalid state!"),
                }
            }
        }

        Ok(num_written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_u8_slice() {
        let data_stream: [u8; 11] = [END, 0xaa, 0xbb, 0xcc, ESC, ESC_END, ESC, ESC_ESC, 0xdd, 0xee, END];
        let mut decoder = Rfc1055Decoder::new(data_stream.into_iter());

        let mut packet: [u8; 7] = [0; 7];
        let read_result = decoder.read(&mut packet[..]);
        assert_eq!(read_result, Ok(7));
        assert_eq!(packet, [0xaa, 0xbb, 0xcc, END, ESC, 0xdd, 0xee]);
    }
}
