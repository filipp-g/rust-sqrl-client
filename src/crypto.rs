use std::hash::Hash;
use std::result;

use hex;
use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::hash::sha256::{Digest, hash};
use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::pwhash::scryptsalsa208sha256;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey};
use sodiumoxide::randombytes;
use text_io::read;
use std::string::FromUtf8Error;

static mut ID_MASTER_KEY: Option<Digest> = None;


pub fn create_identity() {
    // 256 bit value, generated by using sha256 encryption on a randomly selected 32 bit value
    let iuk: Digest = create_iuk();
    println!("ID Unlock Key: {}", hex::encode(iuk.0).to_uppercase());
    // identity masterkey is essentially an encrypted version of the iuk
    let imk: Digest = sqrl_enhash(iuk);
    println!("ID Master Key: {}", hex::encode(imk.0).to_uppercase());
    
	// prompt for the password to be created when we create identity,
    // plus should be verified at login
	println!("\nTo finish creating your identity, please input a password. This password will be");
	println!("used later to confirm your identity before logging you into a website with SQRL.");
    let mut line: String = read!();
	println!("Please confirm your password:");
	let mut passwd: String = read!();
	while line != passwd
	{
		println!("An error occurred: The confirmation did not match your original");
		println!("password. Please try inputting your password again or choose a new one:");
		line = read!();
        println!("Please confirm your password:");
		passwd = read!();
	}

    //get the 256 bit password hash
	let pwh = sqrl_enscrypt(passwd.as_bytes());

    unsafe {
        ID_MASTER_KEY = Option::from(imk);
    }
}

// This might be a serious security violation.
// If we are able to survive without it will delete
pub unsafe fn get_id_masterkey() -> Option<Digest> {
    return ID_MASTER_KEY;
}

// Identity Unlock Key
// SQRL_Cryptography.pdf recommends to create the IUK by harvesting system
// entropy into a SHA512 (or SHA256 - it is unclear if there is a mistake)
// hash in order to create 256 bits of high quality entropy
fn create_iuk() -> Digest {
    // for now just requesting 32 random bytes to shove into SHA256
    let rand: Vec<u8> = randombytes::randombytes(32);
    return hash(&rand);
}

// SQRL EnHash function. generates what will be the identity master key
// to ensure with complete certainty that our function is one-way, we SHA256
// hash the input 16 times, each time XORing the output with previous output
fn sqrl_enhash(input: Digest) -> Digest {
    // do first-pass of SHA256
    let mut digest = hash(input.as_ref());
    // convert to vector to be able to index in
    let mut hashed = digest.as_ref().to_vec();
    let mut xorsum = digest.as_ref().to_vec();
    // do another 15 iterations
    for _ in 0..15 {
        digest = hash(&hashed);
        hashed = digest.as_ref().to_vec();
        for i in 0..xorsum.len() {
            // manual bitwise XOR on output
            xorsum[i] = xorsum[i] ^ hashed[i];
        }
    }
    return Digest::from_slice(&xorsum).unwrap();
}

//SQRL EnScrypt function. SQRL uses the “Scrypt” memory hard function which, 
//in SQRL’s usage, requires a committed block of 16 megabytes of RAM. This moves 
//the function safely out of the range of GPU’s, FPGA’s and ASIC’s. 
//*Input* the password as a *bytestring*, example usage in create_identity
//*Output* This is an std::result Result struct, which basically returns left if Ok() or right if Err()
fn sqrl_enscrypt<'a>(passwd: &'a [u8]) -> Result<[u8; 32], ()>{
    
    let salt = pwhash::gen_salt();

    //the encryption requires a MemLimit struct to specify it as 16mb as per SQRL standard
    let memlimit = scryptsalsa208sha256::MemLimit(16);
    let opslimit = scryptsalsa208sha256::OpsLimit(1024);
    //This gets the key ready to be filled into key
    let mut k = secretbox::Key([0; secretbox::KEYBYTES]);
    let secretbox::Key(mut key) = k;
    
	//Get the 32-byte (256 bits) Password Based Key
    scryptsalsa208sha256::derive_key(&mut key, passwd, &salt, opslimit, memlimit).unwrap();
    
    //println!("Here's the pw hash: {:#?}", key); 
    Ok(key)

} 

// generate the per site public/private keypair using the identity master key and the SQRL domain
// (supplied by the SQRL server and parsed from the SQRL url by us)
pub fn create_keypair(imk: Digest, domain: String) -> (PublicKey, SecretKey)
{
    let domain_as_input = domain.as_bytes();
    let key = &auth::hmacsha256::Key::from_slice(imk.as_ref()).unwrap();

    // crypto::auth::hmacsha256 with domain as input, identity master key as the key, used to
    // generate a seed for the function used to generate the keypair
    // described in  SQRL crypto document pg 10
    let seed = &sign::ed25519::Seed::from_slice(
        auth::hmacsha256::authenticate(domain_as_input, key).as_ref()
    ).unwrap();

    // seed is used to generate the keypair, using crypto::sign::keypair_from_seed
    // also described in SQRL crypto doc pg 10
    let key_pair = sign::keypair_from_seed(seed);

    return key_pair;
}

// using the derived per site private key, creates a signature to be appended to all http queries
// with the SQRL server the SQRL server can verify this signature using the paired public key
// (user identity) sent with the request
pub fn sign_str(input: &str, key: SecretKey) -> String
{
    let input1 = input.as_bytes();

    let signed = sign::sign(input1, &key);

    let tostr = String::from_utf8(signed).unwrap();

    //use the crypto::sign fnxn as described in the SQRL crypto doc pg 10
    return tostr;
}