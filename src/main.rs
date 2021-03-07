use sodiumoxide::randombytes;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::hash::sha256::Digest;


// const TEST_URL: &str = "http://sqrl.grc.com/cli.sqrl?nut=";
// const TEST_NUT: &str = "jLUOj4v1HsZm&can=aHR0cHM6Ly9zcXJsLmdyYy5jb20vZGVtbw";


fn main() {
    let key: Digest = create_iuk();
    println!("{:?}", key);
    let enhashed: Digest = sqrl_enhash(key);
    println!("{:?}", enhashed);
}

// Identity Unlock Key
// SQRL_Cryptography.pdf recommends to create the IUK by harvesting system
// entropy into a SHA512 (or SHA256 - it is unclear if there is a mistake)
// hash in order to create 256 bits of high quality entropy
fn create_iuk() -> Digest {
    // for now just requesting 32 random bytes to shove into SHA256
    let rand: Vec<u8> = randombytes::randombytes(32);
    return sha256::hash(&rand);
}

// SQRL EnHash function
// to ensure with complete certainty that our function is one-way, we SHA256
// hash the input 16 times, each time XORing the output with previous output
fn sqrl_enhash(input: Digest) -> Digest {
    // do first-pass of SHA256
    let mut digest = sha256::hash(input.as_ref());
    // convert to vector to be able to index in
    let mut hashed = digest.as_ref().to_vec();
    let mut xorsum = digest.as_ref().to_vec();
    // do another 15 iterations
    for _ in 0..15 {
        digest = sha256::hash(&hashed);
        hashed = digest.as_ref().to_vec();
        for i in 0..xorsum.len() {
            // manual bitwise XOR on output
            xorsum[i] = xorsum[i] ^ hashed[i];
        }
    }
    return Digest::from_slice(&xorsum).unwrap();
}





// Sample http request function, will use later
// fn send_request(url: &str) -> Result<(), ureq::Error> {
//     let body: String = ureq::get(url)
//         .set("Example-Header", "header value")
//         .call()?
//         .into_string()?;
//     println!("{:?}", body);
//     Ok(())
// }
