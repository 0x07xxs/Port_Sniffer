use std::env;
use std::io::{self, Write};
use std::net::{IpAddr, TcpStream};
use std::str::FromStr;
use std::process;
use std::sync::mpsc::{Sender, channel};
use std::thread;


const MAX: u16 = 65535; // max port number to sniff

struct Arguments {
    flag: String,
    ipaddr: IpAddr, // This is an enum type it can take v4 and v6 ipaddr
    threads: u16,
}

impl Arguments {
    // instantiate the struct
    fn new(args: &[String]) -> Result<Arguments, &'static str> {
        if args.len() < 2 {
            return Err("not enough arguments");
        } else if args.len() > 4 {
            return Err("Too many arguments");
        }
        let f = args[1].clone(); // This will be the IP address
        return if let Ok(ipaddr) = IpAddr::from_str(&f) { // Destruct the IP address to a string
            Ok(Arguments { flag: String::from(""), ipaddr, threads: 4 }) // Default input
        } else {
            let flag = args[1].clone();
            // checking whats inside the flag input
            if flag.contains("-h") || flag.contains("-help") && args.len() == 2 {
                println!("Usage: -j to select how many threads you want
                \r\n    -h or -help to show this help message");
                Err("help")
            } else if flag.contains("-h") || flag.contains("--help") {
                Err("Too many arguments")
            }
            // We get the 3rd index of our input (ipaddress) and convert it into a string
            else if flag.contains("-j") {
                let ipaddr = match IpAddr::from_str(&args[3]) {
                    Ok(s) => s,
                    Err(_) => return Err("Not a valid IPADDR; must be IPv4 or IPv6"),
                };
                // Parses threads from a string to a u16 type
                let threads = match args[2].parse::<u16>() {
                    Ok(s) => s,
                    Err(_) => return Err("failed to parse thread number")
                };
                Ok(Arguments {
                    threads,
                    flag,
                    ipaddr
                })
            } else {
                Err("Invalid syntax")
            }
        }
    }
}

fn scan(tx: Sender<u16>, start_port: u16, addr: IpAddr, num_threads: u16) {
    let mut port: u16 =  start_port + 1;
    loop {
        match TcpStream::connect((addr, port)) {
            Ok(_) => {
                print!(".");
                io::stdout().flush().unwrap();
                tx.send(port).unwrap(); // tx sends rx the open port number
            }
            Err(_) => {}
        }
        if (MAX - port) < num_threads { // if equal to num_threads or 0 break out of the loop
            break;
        }
        port += num_threads; // iterate the port number with the number of threads

    }
}

fn main() {
    let args: Vec<String> = env::args().collect(); // This is getting the arguments and passing it to Vec<String>
    let program = args[0].clone();
    let arguments = Arguments::new(&args).unwrap_or_else(
        |err| {
        if err.contains("help") {
            process::exit(0); // exits the program
        } else {
            eprintln!("{} problem parsing arguments: {}", program, err); // displays the error
                process::exit(0);
        }
    });

    let num_threads = arguments.threads; // number of threads passed in the argument
    let addr = arguments.ipaddr;
    let (tx, rx) = channel(); // tx = transmitter rx = reciever
    for i in 0 .. num_threads {
        let tx = tx.clone(); // each thread will have its own transmitter

        thread::spawn(move || {
            scan(tx, i, addr, num_threads) // we are passing these parameters to the scan func
        });
    }

    let mut out = vec![];
    drop(tx); // drop tx so it can be in the other threads and not in the main thread
    for p in rx {
        // pushing p into the out variable which is a vector
        out.push(p);
    }
    // sorts the values in order
    println!("");
    out.sort();
    for v in out {
        println!("{} is open", v)
    }
}



/*
Expected input:

ip_sniffer.exe -h = help screen
ip_sniffer.exe -j 100 192.168.1.1 = how many threads to use
ip_sniffer.exe 192.168.1.1 = generic input


Definitions:

Vector: Container space to store values in a resizable array type 
Scan(): A Trait for enabling values to be tokenized and then parsed into types implementing FromStr
rx: receives the value from tx
tx: transfers the data into rx 

*/