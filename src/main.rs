extern crate sodiumoxide;
extern crate base64;

use structopt::StructOpt;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::pwhash;
use std::str;
use std::fs::File;
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

    let args = CliOptions {
        mode: String::from("-e"),
        file: std::path::PathBuf::from(fileName),
        passwd: passwd,
    };

    sodiumoxide::init().expect("Failed to initialize sodiumoxide!");

    let file = &mut File::open(args.file.clone()).unwrap();

    encrypt(file, &passwd);
    //decrypt(&args.data);
}

fn encrypt(file: &mut File, passwd: &str) {
    let salt = pwhash::gen_salt();
    let mut key = secretbox::Key([0; secretbox::KEYBYTES]);
    let kb = &mut key.0;
    pwhash::derive_key(kb, passwd.as_bytes(), &salt, pwhash::OPSLIMIT_INTERACTIVE, pwhash::MEMLIMIT_INTERACTIVE).unwrap();

    println!("salt: {:?}", encode(&salt));

    let nonce = secretbox::gen_nonce();

    println!("nonce: {:?}", encode(&nonce));

    let plaintext = b"some data";
    let ciphertext = secretbox::seal(plaintext, &nonce, &key);

    let cipher_string = encode(&ciphertext);
    println!("Data: {}", cipher_string);
}

fn decrypt(data: &String) {
    let s = decode("g2pYvRP6A5jNTXTHet0V7yvMcZGdtZIDPXDHYpSEXRs=").unwrap();
    let n = decode("CBLYh+NAH9u/8IkTV9iR8mNsRgw/cgar").unwrap();

    let payload = decode(data).unwrap();

    let nonce = vec_to_nonce(&n);
    let salt= vec_to_salt(&s);

    let passwd = b"test";

    let mut key = secretbox::Key([0; secretbox::KEYBYTES]);
    let kb = &mut key.0;
    pwhash::derive_key(kb, passwd, &pwhash::Salt(salt), pwhash::OPSLIMIT_INTERACTIVE, pwhash::MEMLIMIT_INTERACTIVE).unwrap();

    let output = secretbox::open(&payload, &secretbox::Nonce(*&nonce), &key).unwrap();
    let output2 = output.iter().map(|&c| c as char).collect::<String>();

    println!("output: {}", output2);
}

fn vec_to_nonce(vec: &Vec<u8>) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(vec);
    nonce
}

fn vec_to_salt(vec: &Vec<u8>) -> [u8; 32] {
    let mut salt = [0u8; 32];
    salt.copy_from_slice(vec);
    salt
}