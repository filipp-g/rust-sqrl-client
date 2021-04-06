use sodiumoxide::init as sodium_init;
use sysinfo::{ProcessExt, SystemExt};
use text_io::read;

mod http;
mod crypto;


fn main() {
    // Initialize the sodiumoxide library. Makes it thread-safe
    sodium_init();


    //Start the server. This prohibits us from using the loop below, since we don't exit. So comment and uncomment as you wish.
    http::start_server();

    // Loop to get user input and navigate through SQRL implementation
    loop {
        println!("Enter in a command. Type 'h' for help with commands");
        // Read input from the user
        let line: String = read!();
        if line == "0" {
            return;
        }
        handle_command(&*line);
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
        "3" => {
            println!("Enter password to view saved urls")
        }
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
    println!("h - Help");
    println!("0 - Exit");
    println!("-------------------------------------");
}

fn cmd_create_identity() {
    println!("Create Identity");
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
        println!("PubKey: {:?}", key_pair.0);
        println!("SecKey: {:?}", key_pair.1);
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