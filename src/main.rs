use std::fs::File;

use base64;
use base64::URL_SAFE_NO_PAD;
use hex;
use sodiumoxide::init as sodium_init;
use sysinfo::{ProcessExt, SystemExt};
use text_io::read;
use tiny_http::{Response, Server};
use std::borrow::Borrow;

mod http;
mod crypto;


fn main() {
    // Initialize the sodiumoxide library. Makes it thread-safe
    sodium_init();

    // Start the server. This prohibits us from using the loop below, since we don't exit.
    // So comment and uncomment as you wish.
    // http::start_server();

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

    // // added some preliminary code to deal with command line args, if we choose to go that route
    // let mut test_url: String = String::from("");
    //
    // for argument in env::args()
    // {
    //     if argument.starts_with("sqrl://")
    //     {
    //         test_url = argument;
    //     }
    // }
    // println!("{:?}", test_url);
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
    println!("3 - Enter Password to view saved urls");
    println!("4 - Start server");
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

pub fn start_server() {
    let server = Server::http("127.0.0.1:25519").unwrap();

    for request in server.incoming_requests() {
        // println!("received {:?} request from url: {:?}", request.method(), request.url());
        println!("{:?}", request);

        if request.url().contains(".gif") {
            let gif = File::open("img/Transparent.gif").unwrap();
            let response = Response::from_file(gif);
            request.respond(response);
        } else {
            let b64 = base64::decode_config(&request.url()[1..], URL_SAFE_NO_PAD).unwrap();
            let url = String::from_utf8(b64).unwrap();

            unsafe {
                let imk = crypto::get_id_masterkey();
                let key_pair = crypto::create_keypair(
                    imk.unwrap(), url.clone()
                );

                let mut clientstr = "ver=1\r\ncmd=query\r\nidk=".to_owned() +
                    &*base64::encode_config(key_pair.0.0, URL_SAFE_NO_PAD) + "\r\n";
                clientstr = base64::encode_config(clientstr, URL_SAFE_NO_PAD);

                let serverstr = base64::encode_config(url, URL_SAFE_NO_PAD);

                let mut idstr = clientstr + &*serverstr;
                idstr = base64::encode_config(
                    crypto::sign_str(&*idstr, key_pair.1), URL_SAFE_NO_PAD
                );

                println!("{:?}", idstr);
            }
        }
    }
}