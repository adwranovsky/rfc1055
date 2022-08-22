#![macro_use]

use std::io::{stdin, stdout, Read, Write, BufReader, BufWriter, ErrorKind};
use std::boxed::Box;
use std::fs::File;
use std::slice;
use rfc1055::nb;
use rfc1055::nb::block;

extern crate clap;
use clap::{Command, arg, ArgMatches, ArgAction, crate_version, crate_authors};


fn main() -> Result<(), std::io::Error> {
    let parsed_args = Command::new("rfc1055-cli")
        .author(crate_authors!("\n"))
        .about("Encode and decode RFC1055 (SLIP) frames")
        .version(crate_version!())
        .subcommand_required(true)
        .subcommand(
            Command::new("decode")
                .about("Decode RFC1055 frames")
                .arg(
                    arg!(
                        -d --discard "Discard all input up to the first END character received"
                    )
                    .action(ArgAction::SetTrue)
                )
                .arg(
                    arg!(
                        -i --input <input> "The path to the file to use as input. If \"-\" or no file is specified, use stdin."
                    )
                    .required(false)
                )
                .arg(
                    arg!(
                        [output] ... "The output files to write in-order. Each will contain the content of a single decoded packet. If \"-\" or no file is specified, use stdout."
                    )
                    .default_value("-")
                )
        )
        .subcommand(
            Command::new("encode")
                .about("Encode RFC1055 frames")
                .arg(
                    arg!(
                        -o --output <output> "The path to the file to use as output. If \"-\" or no file is specified, use stdout."
                    )
                    .required(false)
                )
                .arg(
                    arg!(
                        [input] ... "The input files to write in-order to the output. Each is encoded as a separate packet. If \"-\" or no file is specified, use stdin"
                    )
                    .default_value("-")
                )
        )
        .after_help(
            "More information about the SLIP protocol can be found here: https://datatracker.ietf.org/doc/html/rfc1055"
        )
        .get_matches();

    match parsed_args.subcommand() {
        Some(("decode", sub_matches)) => {
            decode_command(sub_matches)
        },
        Some(("encode", sub_matches)) => {
            encode_command(sub_matches)
        },
        _ => unreachable!(),
    }
}

fn encode_command(matches: &ArgMatches) -> Result<(), std::io::Error> {
    // Get the selected data sink
    let mut writer: BufWriter<Box<dyn Write>> = match matches.get_one::<String>("output") {
        Some(path) if path != "-" => {
            BufWriter::new(Box::new(
                File::options()
                    .create(true)
                    .write(true)
                    .open(path)?
            ))
        },
        _ => {
            BufWriter::new(Box::new(stdout()))
        },
    };

    // Create the encoder from the sink
    let mut encoder = rfc1055::Encoder::new(
        move |b: u8| {
            match writer.write(slice::from_ref(&b)) {
                Ok(0) => Err(nb::Error::Other(())),
                Ok(_) => Ok(()),
                Err(e) if e.kind() == ErrorKind::Interrupted => Err(nb::Error::WouldBlock),
                Err(_) => Err(nb::Error::Other(())),
            }
        }
    );

    // Iterate through all input files in order
    for input_file_path in matches.get_many::<String>("input").expect("an input file is required") {
        // Read input to EOF and convert to u8 slice
        let input = if input_file_path == "-" {
            let mut input_vec: Vec<u8> = Vec::new();
            stdin().read_to_end(&mut input_vec)?;
            input_vec
        } else {
            let mut input_vec: Vec<u8> = Vec::new();
            File::open(input_file_path)?.read_to_end(&mut input_vec)?;
            input_vec
        };
        let input = input.as_slice();

        // Encode the whole input as a single packet, bailing on IO errors
        let mut num_written = 0;
        loop {
            num_written += match block!(encoder.write(&input[num_written..])) {
                Ok(n) => n,
                Err(_) => { return Err(std::io::Error::last_os_error()); },
            };

            if num_written == input.len() {
                break;
            }
        }
    }

    Ok(())
}

fn decode_command(matches: &ArgMatches) -> Result<(), std::io::Error> {
    // Get the selected data source
    let mut reader: BufReader<Box<dyn Read>> = match matches.get_one::<String>("input") {
        Some(path) if path != "-" => BufReader::new(Box::new(File::open(path)?)),
        _ => BufReader::new(Box::new(stdin())),
    };

    // Create the decoder from the source
    let discard = *matches.get_one::<bool>("discard").unwrap();
    let mut decoder = rfc1055::Decoder::new(
        move || {
            let mut b: [u8; 1] = [0];
            match reader.read(&mut b[..]) {
                Ok(0) => Err(nb::Error::Other(())),
                Ok(_) => Ok(b[0]),
                Err(e) if e.kind() == ErrorKind::Interrupted => Err(nb::Error::WouldBlock),
                Err(_) => Err(nb::Error::Other(())),
            }
        },
        discard,
    );

    // Iterate through all all output files in order
    for output_file_path in matches.get_many::<String>("output").expect("an output file is required") {
        // Open the current data sink
        let mut output: BufWriter<Box<dyn Write>> = match output_file_path as &str {
            "-" => BufWriter::new(Box::new(stdout())),
            p => BufWriter::new(Box::new(File::options().create(true).write(true).open(p)?)),
        };

        // Decode a whole, singular packet, bailing on IO errors
        loop {
            // Read up to 1 kB at a time
            let mut buffer: [u8; 1024] = [0; 1024];
            let num_read = match block!(decoder.read(&mut buffer[..])) {
                Ok(0) => { break; },
                Ok(n) => n,
                Err(_) => { break; },
            };

            // Write to the data sink
            output.write_all(&buffer[..num_read])?;
        }
    }

    Ok(())
}
