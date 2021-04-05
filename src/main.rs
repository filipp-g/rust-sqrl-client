use sodiumoxide::init as sodium_init;
use sysinfo::{ProcessExt, SystemExt};
use text_io::read;

mod http;
mod crypto;


fn main() {
    // Initialize the sodiumoxide library. Makes it thread-safe
    sodium_init();

    //Loop to get user input and navigate through SQRL implementation
    let arr: [&str; 4] = ["h", "1", "2", "3"];
    loop {
        println!("Enter in a command. Type 'h' for help with commands");
        //Read input from the user
        let mut line: String = read!("{}\n");
        let mut command: bool = false;
        //checks over the array to see if it's a valid command
        for x in 0..arr.len() {
            if arr[x] == line {
                command = true;
            }
        }
        if command {
            handle_command(&*line)
        } else if line == "0" {
            return;
        } else {
            println!("Not a valid command. Type 'h' to view list of commands");
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

//Handles the command input by the user.
fn handle_command(com: &str) {
    if com == "h" {
        println!("LIST OF COMMANDS");
        println!("1 - Create Identity");
        println!("2 - Create keys for url");
        println!("3 - Enter Password to view saved urls");
        println!("h - Help");
        println!("0 - Exit");
        println!("-------------------------------------");
    }
    //Create Identity command
    else if com == "1" {
        println!("Create Identity");
        unsafe {
            if crypto::get_id_masterkey() != None {
                println!("Identity already exists. Overwrite? [y/N]");
                let choice: String = read!("{}");
                if choice != "y" && choice != "Y" {
                    return;
                }
            }
            crypto::create_identity();
            println!("Identity created successfully");
        }
    }
    //Create Keys for URL
    else if com == "2" {
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

        // if you would like to test the parsing functions simply uncomment these lines, recompile,
        // and run the executable. feel free to add more test cases in these functions
        //test_parse_nut();
        //test_parse_domain();
    }
    //Enter password to view saved urls
    else if com == "3" {
        println!("Enter password to view saved urls");
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