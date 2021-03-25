use sodiumoxide::randombytes;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::hash::sha256::Digest;
use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::ed25519::PublicKey;
use sodiumoxide::crypto::sign::ed25519::SecretKey;

const TEST_URL: &str = "http://sqrl.grc.com/cli.sqrl?nut=";
// const TEST_NUT: &str = "jLUOj4v1HsZm&can=aHR0cHM6Ly9zcXJsLmdyYy5jb20vZGVtbw";


fn main() {
    let iuk: Digest = create_iuk();
    println!("{:?}", iuk);
    let enhashed: Digest = sqrl_enhash(iuk);
    println!("{:?}", enhashed);

	let key_pair = create_keypair(iuk, parse_domain(TEST_URL));
	println!("{:?}", key_pair);


	//if you would like to test the parsing functions simply uncomment these lines, recompile, and run the executable. feel free to add more test cases in these functions
	//test_parse_nut(); 
	//test_parse_domain();

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

//generate the per site public/private keypair using the identity master key and the SQRL domain (supplied by the SQRL server and parsed from the SQRL url by us)
fn create_keypair(imk: Digest, domain: String) -> ( PublicKey, SecretKey )
{
	let domain_as_input = domain.as_bytes();
	let key = &auth::hmacsha256::Key::from_slice(imk.as_ref()).unwrap();

	//crypto::auth::hmacsha256 with domain as input, identity master key as the key, used to generate a seed for the function used to generate the keypair
	//described in  SQRL crypto document pg 10
	let seed = &sign::ed25519::Seed::from_slice( auth::hmacsha256::authenticate(domain_as_input, key).as_ref() ).unwrap();
	
	//seed is used to generate the keypair, using crypto::sign::keypair_from_seed
	//also described in SQRL crypto doc pg 10
	let key_pair = sign::keypair_from_seed(seed);

	return key_pair;
}


//Parsing function to get back just the 'nut' portion of the URL
fn parse_nut(url: &str) -> String
{
	let mut nut: String = String::from("");
	if url.starts_with("sqrl://") 
    {   
		let mut temp_url = url.strip_prefix("sqrl://").unwrap();

		temp_url = temp_url.split("?").collect::<Vec<&str>>()[1];	
		
		temp_url = temp_url.split("nut=").collect::<Vec<&str>>()[1];	

		temp_url = temp_url.split("&can=").collect::<Vec<&str>>()[0];

		nut.push_str(temp_url);
		
		return nut;
    }
    else
    {
		nut.push_str("Error");
        return nut;
    }
}

fn test_parse_nut()
{

	assert_eq!("jLUOj4v1HsZm", parse_nut("sqrl://sqrl.grc.com/cli.sqrl?nut=jLUOj4v1HsZm&can=aHR0cHM6Ly9zcXJsLmdyYy5jb20vZGVtbw"));

}

//Parsing function to get back just the domain portion of the URL
//the exact domain is required to compute the per site private key
//we can fix formatting on the fnxn to get rid of empty lines, I just like to have my code spread out and separated so its easy to read
fn parse_domain(url: &str) -> String
{
	// url param is the SQRL url that looks like: sqrl://example.com/jimbo/?x=6&nut=... need to parse out the "example.com/jimbo"

	if url.starts_with("sqrl://") 
    {   
		let mut domain: String = String::from("");
		let mut temp_url = url.strip_prefix("sqrl://").unwrap();
		let offset = determine_offset(temp_url.split("?").collect::<Vec<&str>>()[1]);

		temp_url = temp_url.split("?").collect::<Vec<&str>>()[0];	

		if temp_url.find("@") != None
		{
			temp_url = temp_url.split("@").collect::<Vec<&str>>()[1];  //keep things to the right of the @ symbol
		}
		
		let mut end_index = temp_url.find("/").unwrap() as u8;	//domain ends at the beginning of the first '/' symbol, eg example.com/ 
																//unless theres an extension, which is then given by the offset var
		let mut index = 0;
		for character in temp_url.chars()
		{
			if index == (end_index + offset) || character == '?'
			{
				break;
			}
			else if index < end_index && (character.is_alphabetic() || character == '.')
			{
				domain.push(character.to_ascii_lowercase()); 
			}
			else if index >= end_index && index < (end_index + offset)
			{
				domain.push(character);
			}
			
			index += 1;
		}	

		return domain;
    }
    else
    {
        return String::from("Error");
    }
}

//Helper function for the parsers
fn determine_offset(params: &str) -> u8
{
	//given something like x=5&nut=oOB4QOFJux5Z&can=aHR0cHM6Ly9zcXJsLmdyYy5jb20vYWNjb3VudC9jb25uZWN0ZWQtYWNjb3VudHMv
	
	if params.get(0..1).unwrap() == "x"
	{
		let mut num_str = params.split("&").collect::<Vec<&str>>()[0];
		num_str = num_str.split("=").collect::<Vec<&str>>()[1];

		return num_str.parse::<u8>().unwrap();
	}
	return 0;
}


fn test_parse_domain()
{
	//test cases taken from GRCs SQRL Operating Details pg 7
	
	assert_eq!(String::from("example.com"),   parse_domain("sqrl://ExAmPlE.cOm/?nut="));   // to lowercase

	assert_eq!(String::from("example.com"),   parse_domain("sqrl://example.com:44344/?nut="));   //removing specified port num

	assert_eq!(String::from("example.com"),   parse_domain("sqrl://jonny@example.com/?nut="));    //removing username prefix

	assert_eq!(String::from("example.com"),   parse_domain("sqrl://Jonny:Secret@example.com/?nut="));  //removing username:pass prefix

	assert_eq!(String::from("example.com/jimbo"),   parse_domain("sqrl://example.com/jimbo/?x=6&nut="));  //keeping extended auth domain

	assert_eq!(String::from("example.com/JIMBO"),   parse_domain("sqrl://EXAMPLE.COM/JIMBO?x=16&nut="));  //stopping at ? and only making domain lowercase, not extended auth

	assert_eq!(String::from("sqrl.grc.com/demo"),   parse_domain("sqrl://steve:badpass@SQRL.grc.com:8080/demo/cli.sqrl?x=5&nut=oOB4QOFJux5Z&
can=aHR0cHM6Ly9zcXJsLmdyYy5jb20vYWNjb3VudC9jb25uZWN0ZWQtYWNjb3VudHMv"));


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
