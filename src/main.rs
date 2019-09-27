extern crate sodiumoxide;
extern crate base64;

use structopt::StructOpt;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::pwhash;
use std::str;
use std::fs;
use std::fs::File;
use std::{error, fmt};
use std::io::prelude::*;
use std::path::PathBuf;
use base64::{encode, decode};

#[derive(StructOpt)]
struct CliOptions {
    mode: String,
    #[structopt(parse(from_os_str))]
    file: std::path::PathBuf,
    passwd: String,
}

fn main() {
    let fileName = std::env::args().nth(1).expect("no string provided!");
    let passwd = std::env::args().nth(2).expect("no password provided!");
    let mode = std::env::args().nth(3).expect("please use -e for encryption or -d for decryption");

    let args = CliOptions {
        mode: mode,
        file: std::path::PathBuf::from(fileName),
        passwd: passwd,
    };

    sodiumoxide::init().expect("Failed to initialize sodiumoxide!");

    if(args.mode == "-e") {
        encrypt(args.file, &args.passwd);
    } else {
        decrypt(args.file, args.passwd);
    }
}

fn encrypt(file: PathBuf, passwd: &str) {
    // Both the nonce and salt are randomly generated on outfile creation.
    let salt = pwhash::gen_salt();
    let nonce = secretbox::gen_nonce();

    // This allows us to specific our password / key by pre-allocating [u8; N] with the key-size and filling it afterwards.
    let mut key = secretbox::Key([0; secretbox::KEYBYTES]);
    let kb = &mut key.0;
    pwhash::derive_key(kb, passwd.as_bytes(), &salt, pwhash::OPSLIMIT_INTERACTIVE, pwhash::MEMLIMIT_INTERACTIVE).unwrap();

    // This reads the entire file into memory as a string, obviously not ideal for large-file encryption
    // I didn't have time to implement large-file encryption via a stream cipher or chunk-based encryption so this will have to do :)
    let contents = fs::read_to_string(&file).unwrap();

    let ciphertext = secretbox::seal(contents.as_bytes(), &nonce, &key);

    let mut outFile = File::create(file).unwrap();
    outFile.set_len(0); // this will effectively delete the original contents from the file.
    outFile.write(&salt.0);
    outFile.write(&nonce.0);
    outFile.write(&ciphertext);
}

fn decrypt(filePath: PathBuf, passwd: String) {
    let mut file = File::open(&filePath).unwrap();

    if !(file.metadata().unwrap().len() > (pwhash::SALTBYTES + secretbox::NONCEBYTES) as u64) {
        return;
    }

    let mut salt = [0u8; pwhash::SALTBYTES];
    let mut nonce = [0u8; secretbox::NONCEBYTES];

    // this is a standard calculation, as salt is locked to 32 bytes and the nonce is 24 bytes
    // we can always expect the payload size to be the file length in bytes - the amount of bytes we have read.
    // we must set this to a Vec<u8> as we cannot create an array of ( unknown-size at compile-time )
    let mut payload = vec![0u8; (file.metadata().unwrap().len() - 56) as usize];

    file.read_exact(&mut salt);
    file.read_exact(&mut nonce);
    file.read(&mut payload);

    let salt = pwhash::Salt(salt);
    let nonce = secretbox::Nonce(*&nonce);

    let mut key = secretbox::Key([0; secretbox::KEYBYTES]);
    let kb = &mut key.0;

    pwhash::derive_key(kb, passwd.as_bytes(), &salt,
                       pwhash::OPSLIMIT_INTERACTIVE, pwhash::MEMLIMIT_INTERACTIVE).unwrap();

    let output = secretbox::open(&payload, &nonce, &key).unwrap();
    let output_string = output.iter().map(|&c| c as char).collect::<String>();


    // Manually close the file because we plan on writing to the same file directory afterwards.
    drop(file);

    let mut outFile = File::create(&filePath).unwrap();
    outFile.set_len(0);
    outFile.write(&output);

}

// Both of these functions are only used to test functionality while file-encryption and headers are being written.
fn vec_to_nonce(vec: &Vec<u8>) -> [u8; secretbox::NONCEBYTES] {
    let mut nonce = [0u8; secretbox::NONCEBYTES];
    nonce.copy_from_slice(vec);
    nonce
}

fn vec_to_salt(vec: &Vec<u8>) -> [u8; pwhash::SALTBYTES] {
    let mut salt = [0u8; pwhash::SALTBYTES];
    salt.copy_from_slice(vec);
    salt
}