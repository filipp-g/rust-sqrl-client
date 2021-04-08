use std::fs::File;

use base64;
use base64::URL_SAFE_NO_PAD;
use hex;
use sodiumoxide::crypto::sign::SecretKey;
use sodiumoxide::init as sodium_init;
use sysinfo::{ProcessExt, SystemExt};
use text_io::read;
use tiny_http::{Header, Request, Response, Server};
use ureq;

mod http;
mod crypto;


fn main() {
    // Initialize the sodiumoxide library. Makes it thread-safe
    if sodium_init().is_err() {
        println!("Unable to initialize sodiumoxide")
    }

    // Loop to get user input and navigate through SQRL implementation
    loop {
        println!("\nEnter in a command. Type 'h' for help with commands");
        // Read input from the user
        let line: String = read!();
        if line.eq("0") {
            return;
        }
        if ["h", "1", "2", "3", "4"].contains(&&*line) {
            handle_command(&*line);
        }
    }
}

// Handles the command input by the user.
fn handle_command(command: &str) {
    match command {
        "h" => { print_commands_list() }
        "1" => { cmd_create_identity() }
        "2" => { cmd_create_url_keypair() }
        "3" => { start_server() }
        _ => {
            println!("Not a valid command. Type 'h' to view list of commands")
        }
    }
}

fn print_commands_list() {
    println!("LIST OF COMMANDS");
    println!("1 - Create Identity");
    println!("2 - Create keys for url");
    println!("3 - Start server");
    println!("h - Help");
    println!("0 - Exit");
    println!("-------------------------------------");
}

fn cmd_create_identity() {
    println!("Creating Identity...");
    unsafe {
        if crypto::get_id_masterkey() != None {
            println!("Identity already exists. Overwrite? [y/N]");
            let choice: String = read!();
            if choice != "y" && choice != "Y" {
                return;
            }
        }
    }
    crypto::create_identity();
    println!("Identity created successfully");
}

fn cmd_create_url_keypair() {
    println!("Enter URL to create keys: ");
    let url: String = read!();
    let domain = http::parse_domain(&*url);
    if domain == "Error" {
        println!("Not valid sqrl:// URL");
        return;
    }
    unsafe {
        let imk = crypto::get_id_masterkey();
        if imk == None {
            println!("Please create an Identity first");
            return;
        }
        // per-site public/private keys derived from the imk and the domain from the sqrl URL
        let key_pair = crypto::create_keypair(imk.unwrap(), domain);
        println!("PubKey: {}", hex::encode(key_pair.0.0).to_uppercase());
        println!("SecKey: {}", hex::encode(key_pair.1.0).to_uppercase());
    }
}

pub fn start_server() {
    let server = Server::http("127.0.0.1:25519").unwrap();

    for request in server.incoming_requests() {
        println!("{:?}", request);

        if request.url().contains(".gif") {
            handle_gif_response(request);
        } else if !request.url().contains(".ico") {
            handle_auth_response(request);
        }
    }
}

fn handle_auth_response(request: Request) {
    let url = base64decode(&request.url()[1..]);
    let original = url.strip_prefix("sqrl://")
        .unwrap()
        .split("/")
        .collect::<Vec<&str>>()[0];

    let imk;
    unsafe {
        // IMK is saved as static global thus not threadsafe
        imk = crypto::get_id_masterkey().unwrap();
    }
    let key_pair = crypto::create_keypair(imk, url.clone());
    let seckey: SecretKey = key_pair.1;
    let b64pubkey: String = base64encode(key_pair.0.0);

    let mut clientstr = format!("ver=1\r\ncmd=query\r\nidk={}\r\nopt=cps\r\n", b64pubkey);
    clientstr = base64encode(clientstr);

    let serverstr = base64encode(url.clone());

    let mut idstr = clientstr.clone() + &*serverstr.clone();
    idstr = base64encode(crypto::sign_str(&*idstr, seckey.clone()));

    let httpurl = str::replace(&*url, "sqrl://", "http://");

    let response = ureq::post(&*httpurl)
        .send_form(&[
            ("client", &*clientstr),
            ("server", &*serverstr),
            ("ids", &*idstr),
        ]);

    let string_resp = response.unwrap().into_string().unwrap();
    println!("server resp = {:?}", string_resp);
    println!("decoded:\n{}", base64decode(string_resp.clone()));

    //send second 'ident' request
    clientstr = format!("ver=1\r\ncmd=ident\r\nidk={}\r\nopt=cps\r\n", b64pubkey);
    clientstr = base64encode(clientstr);

    //make server value
    let mut newurl = base64decode(string_resp.clone());
    newurl = newurl.split("qry=").collect::<Vec<&str>>()[1].trim().to_string();
    newurl = format!("http://{}{}", original, newurl);
    println!("new url to send to server = {}", newurl);

    idstr = clientstr.clone() + &*serverstr.clone();
    //create the signature from client+server concatenated
    idstr = base64encode(crypto::sign_str(&*idstr, seckey));

    let server_response2 = ureq::post(&*newurl)
        .send_form(&[
            ("client", &*clientstr),
            ("server", &*string_resp),
            ("ids", &*idstr),
        ]).unwrap();

    let string_resp2 = server_response2.into_string().unwrap();
    newurl = base64decode(string_resp2.clone());
    println!("last check, server resp decoded:\n{}", newurl);

    if newurl.contains("url=") {
        let redirect = newurl.split("url=")
            .collect::<Vec<&str>>()[1]
            .trim()
            .to_string();
        println!("redrect url should be = {}", redirect);

        let browser_resp = Response::from_string("body-goes-here")
            .with_header(Header::from_bytes("Location", redirect).unwrap())
            .with_status_code(302);

        if request.respond(browser_resp).is_err() {
            println!("Error: unable to respond to browser with 302")
        }
    }
}

fn handle_gif_response(request: Request) {
    let gif = File::open("img/Transparent.gif").unwrap();
    let response = Response::from_file(gif);
    if request.respond(response).is_err() {
        println!("Error: unable to respond with .gif")
    }
}

// convenience function for encoding as base64url
fn base64encode<T: AsRef<[u8]>>(input: T) -> String {
    return base64::encode_config(input, URL_SAFE_NO_PAD);
}

// convenience function for decoding base64url
fn base64decode<T: AsRef<[u8]>>(input: T) -> String {
    let utf8 = base64::decode_config(input, URL_SAFE_NO_PAD).unwrap();
    return String::from_utf8(utf8).unwrap();
}

// can use this once we figure out how to either do IPC or send kill
// signal to already running non-child process
fn check_processes() {
    let mut system = sysinfo::System::new_all();
    // Need to update all information of system struct
    system.refresh_all();
    for (pid, proc_) in system.get_processes() {
        if proc_.name().starts_with("rust-sqrl-client") {
            println!("{}:{} => status: {:?}", pid, proc_.name(), proc_.status());
        }
    }
}
