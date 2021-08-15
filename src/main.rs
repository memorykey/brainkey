extern crate argparse;
extern crate crypto;
extern crate termion;
extern crate rand;
extern crate rand_chacha;
extern crate bip39;

use argparse::{ArgumentParser, Store, StoreTrue};
use std::fmt::Write as FmtWrite;
use termion::input::TermRead;
use std::io::{Write, stdout, stdin, Read, Seek, SeekFrom};
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use std::{process, fs};
use std::fs::OpenOptions;
use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::chacha20::ChaCha20;
use std::collections::HashMap;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand::distributions::Uniform;
use bip39::{Mnemonic, Language};

const BUFFER_SIZE : usize = 4096;

fn main() {
    let mut size = 16;
    let mut difficulty = 21;
    let mut saltstr = "salt".to_string();
    let mut kv = "".to_string();
    let mut crypt_file = "".to_string();
    let mut crypt_length = 0;
    let mut in_key_string = "".to_string();
    let mut out_key_string = "".to_string();
    let mut in_is_out = false;
    let mut shuffle = false;
    let mut bip39_output = false;
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("brainkey key generator");
        ap.refer(&mut size)
            .add_option(&["--size"], Store, "Size of output in bytes");
        ap.refer(&mut difficulty)
            .add_option(&["--difficulty"], Store, "Difficulty factor");
        ap.refer(&mut saltstr)
            .add_option(&["--salt"], Store, "Salt value");
        ap.refer(&mut kv)
            .add_option(&["--kv"], Store, "Key verification code");
        ap.refer(&mut crypt_file)
            .add_option(&["--crypt"], Store, "Also crypt file");
        ap.refer(&mut crypt_length)
            .add_option(&["--max"], Store, "Maximum crypt length");
        ap.refer(&mut in_key_string)
            .add_option(&["--inkey"], Store, "Use string for input instead of console");
        ap.refer(&mut in_is_out)
            .add_option(&["--readoutkey"], StoreTrue, "Read output key for further operations from console");
        ap.refer(&mut out_key_string)
            .add_option(&["--outkey"], Store, "Use specified output key for further operations");
        ap.refer(&mut shuffle)
            .add_option(&["--permute"], StoreTrue, "Key character permutation (tty only)");
        ap.refer(&mut bip39_output)
            .add_option(&["--bip39"], StoreTrue, "Output as a bip39 phrase");
        ap.parse_args_or_exit();
    }
    let salt: &[u8] = saltstr.as_bytes();

    let mut resvector = vec![0;size];
    let mut result: &mut [u8];
    if out_key_string.is_empty() {
        result = resvector.as_mut_slice();
        let password;
        if !in_key_string.is_empty() {
            password = in_key_string;
        } else {
            let stdout = stdout();
            let mut stdout = stdout.lock();
            let stdin = stdin();
            let mut stdin = stdin.lock();

            let mut shuffle_map = HashMap::new();
            if shuffle {
                let mut rand = ChaCha20Rng::from_entropy();
                let chars : Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*(),./<>?-=_+`~;':\"".chars().collect();
                let dist = Uniform::new(0, chars.len());
                let mut chars_shuffled = chars.clone();
                for n in 0..chars.len() {
                    let r = rand.sample(dist);
                    let tmp = chars_shuffled[n];
                    chars_shuffled[n] = chars_shuffled[r];
                    chars_shuffled[r] = tmp;
                }
                for n in 0..chars.len() {
                    shuffle_map.insert(chars_shuffled[n], chars[n]);
                }
                let rows = chars.len()/8;
                for n in 0..rows {
                    print!("{}: {}", chars[n], chars_shuffled[n]);
                    print!("     {}: {}", chars[n+rows], chars_shuffled[n+rows]);
                    print!("     {}: {}", chars[n+rows*2], chars_shuffled[n+rows*2]);
                    print!("     {}: {}", chars[n+rows*3], chars_shuffled[n+rows*3]);
                    print!("     {}: {}", chars[n+rows*4], chars_shuffled[n+rows*4]);
                    print!("     {}: {}", chars[n+rows*5], chars_shuffled[n+rows*5]);
                    print!("     {}: {}", chars[n+rows*6], chars_shuffled[n+rows*6]);
                    print!("     {}: {}", chars[n+rows*7], chars_shuffled[n+rows*7]);
                    println!();
                }
            }

            if termion::is_tty(&stdin) {
                stdout.write_all(b"Phrase: ").unwrap();
                stdout.flush().unwrap();
            }

            password = if termion::is_tty(&stdout) {
                let raw = stdin.read_passwd(&mut stdout).unwrap().unwrap();
                let raw_chars : Vec<char> = raw.chars().collect();
                if shuffle {
                    let mut permuted : String = "".to_string();
                    for i in 0..raw_chars.len() {
                        let c = raw_chars[i];
                        let mut pc = c;
                        if shuffle_map.contains_key(&pc) {
                            pc = shuffle_map[&pc];
                        }
                        permuted.push(pc);
                    }
                    permuted
                } else {
                    raw
                }
            } else {
                stdin.read_line().unwrap().unwrap()
            };
        }

        if in_is_out {
            // Entered string is hex output
            resvector = hex::decode(password).unwrap();
            result = resvector.as_mut_slice();
        } else {
            let password = password.trim_end_matches("\n");
            let pwdbytes = password.as_bytes();
            let params = crypto::scrypt::ScryptParams::new(difficulty, 8, 1);
            crypto::scrypt::scrypt(pwdbytes, salt, &params, &mut result);
        }
    } else {
        // Specified output directly, so just decode the hex
        resvector = hex::decode(out_key_string).unwrap();
        result = resvector.as_mut_slice();
    }
    if !kv.is_empty() {
        let mut hasher = Sha256::new();
        hasher.input(result.as_ref());
        let kv_hex = hasher.result_str()[..kv.len()].to_string();
        if kv_hex != kv {
            println!("\nMismatched kv, got {}", kv_hex);
            process::exit(0x01);
        }
    }
    if !crypt_file.is_empty() {
        crypt(crypt_file, result, crypt_length);
    }
    if bip39_output {
        let mnemonic = Mnemonic::from_entropy(result, Language::English).unwrap();
        println!("\n{}", mnemonic.into_phrase());
    } else {
        println!("\n{}", hex::encode(result));
    }
}

fn crypt(file_path: String, key_bytes: &mut [u8], mut crypt_length: u64) {
    // Salted based on file length only
    // Length preserving, change in-place
    if crypt_length == 0 {
        crypt_length = fs::metadata(&file_path).unwrap().len();
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path).unwrap();
    let mut position : u64 = 0;
    let mut buffer_vector = vec![0;BUFFER_SIZE];
    let mut read_amount;

    let key = key_bytes;
    let mut length_string = String::new();
    write!(&mut length_string, "{:08x}", crypt_length).unwrap();
    let nonce = length_string.as_bytes();
    let mut cipher = ChaCha20::new(&key, &nonce);

    while position < crypt_length {
        file.seek(SeekFrom::Start(position)).unwrap();
        {
            let mut read_length = (crypt_length - position) as usize;
            if read_length > BUFFER_SIZE {
                read_length = BUFFER_SIZE;
            }
            let buffer : &mut[u8] = buffer_vector.as_mut_slice()[0..read_length].as_mut();
            read_amount = file.read(buffer).unwrap();
            if read_amount == 0 {
                break;
            }
        }
        file.seek(SeekFrom::Start(position)).unwrap();
        {
            let part_buffer = &buffer_vector[0..read_amount];
            let mut crypto_buffer = vec![0;read_amount];
            cipher.process(part_buffer, crypto_buffer.as_mut_slice());
            file.write(crypto_buffer.as_slice()).unwrap();
        }
        position += read_amount as u64;
    }
}
