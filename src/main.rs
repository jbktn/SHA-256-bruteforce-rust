extern crate rand;
extern crate sha2;
extern crate rayon;
extern crate itertools;

use rand::seq::SliceRandom;
use rand::thread_rng;
use sha2::{Sha256, Digest};
use std::io::{self};
use std::time::Instant;
use itertools::Itertools;
use rayon::prelude::*;

fn main() {
    println!("Enter hash: ");
    let mut passwd = String::new();
    io::stdin().read_line(&mut passwd).expect("Failed to read line");
    let passwd = passwd.trim().to_string();

    println!("1 - digits\n2 - alpha\n3 - lowercase\n4 - simple\n5 - extended");
    let mut mode = String::new();
    io::stdin().read_line(&mut mode).expect("Failed to read line");
    let mode: u32 = mode.trim().parse().expect("Please enter a number");

    let digits: Vec<char> = ('0'..='9').collect();
    let alpha: Vec<char> = ('a'..='z').chain('A'..='Z').collect();
    let charset_lower: Vec<char> = ('a'..='z').collect();
    let charset_simple: Vec<char> = ('0'..='9')
        .chain('a'..='z')
        .chain('A'..='Z')
        .collect();
    let charset_extended: Vec<char> = ('0'..='9')
        .chain('a'..='z')
        .chain('A'..='Z')
        .chain("-_+!@#$%^&*=![{]/?.:,<>:;'| ".chars())
        .collect();

    let charset = match mode {
        1 => digits,
        2 => alpha,
        3 => charset_lower,
        4 => charset_simple,
        5 => charset_extended,
        _ => {
            println!("Invalid mode");
            return;
        }
    };

    brute_force(charset, passwd);
}

fn brute_force(charset: Vec<char>, password: String) {
    let mut rng = thread_rng();
    let mut charset = charset.clone();
    charset.shuffle(&mut rng);

    let mut length = 1;
    let t1 = Instant::now();

    loop {
        let found = (0..charset.len().pow(length as u32))
            .into_par_iter()
            .map(|index| {
                let mut generated = vec![' '; length];
                let mut idx = index;
                for i in 0..length {
                    generated[i] = charset[idx % charset.len()];
                    idx /= charset.len();
                }
                let gen: String = generated.iter().collect();
                let mut hasher = Sha256::new();
                hasher.update(gen.as_bytes());
                let result = hasher.finalize();
                let g = format!("{:x}", result);
                (gen, g)
            })
            .find_any(|(_, g)| g == &password);

        if let Some((gen, g)) = found {
            let t2 = Instant::now();
            println!(
                "\x1b[31mpassword: {} \x1b[0m | hashed: {}",
                gen, g
            );
            println!(
                "time: {:?}s | length: {}",
                t2 - t1,
                length
            );
            return;
        }
        length += 1;
    }
}
