#![macro_use]

use std::io::{stdin, stdout, Read, Write, BufReader, BufWriter, ErrorKind};
use std::boxed::Box;
use std::fs::File;
use std::slice;
use rfc1055::nb;
use rfc1055::nb::block;

extern crate clap;
use clap::{Command, Arg, arg, ArgMatches, crate_version, crate_authors};


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
                    Arg::with_name("output")
                         .short('o')
                         .long("output")
                         .value_name("output")
                         .help("The path to the file to use as output. If \"-\" or no file is specified, use stdout.")
                         .takes_value(true)
                )
                .arg(
                    Arg::with_name("input")
                        .short('i')
                        .long("input")
                        .value_name("input")
                        .help("The path to the file to use as input. If \"-\" or no file is specified, use stdin.")
                        .takes_value(true)
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
        Some(path) if path != "-" => { todo!("Implement opening files") },
        _ => { BufWriter::new(Box::new(stdout())) },
    };

    // Create the encoder from the sink
    let mut encoder = rfc1055::Encoder::new(
        move |b: u8| {
            match writer.write(slice::from_ref(&b)) {
                Ok(0) => { Err(nb::Error::Other(())) },
                Ok(n) => { Ok(()) },
                Err(e) if e.kind() == ErrorKind::Interrupted => { Err(nb::Error::WouldBlock) },
                Err(_) => { Err(nb::Error::Other(())) },
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
                Ok(n) => { n },
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
    Ok(())
}
