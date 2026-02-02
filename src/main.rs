use nfq::{Queue, Verdict};
use std::io::Write;
use std::process::Command; // needed this for flush the buffer
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn main() {
    let nfq_num = 0;
    let _rules = IpTablesRedirector::new(nfq_num);
    let mut pckt_count: u64 = 0;
    let mut queue = Queue::open().expect("[ERROR] Failed to open NFQUEUE");
    queue
        .bind(nfq_num)
        .expect("[ERROR] Failed to bind to queue");

    // wrap it in arc so we can share it between two pieces of code
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // set the handler
    ctrlc::set_handler(move || {
        println!("\n[INFO] Ctrl+C received! Stopping...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("[ERROR] Failed setting Ctrl-C handler");

    println!("Listening for packets... (Press CTRL+C to quit.)");

    while running.load(Ordering::SeqCst) {
        // queue.recv() waits for a packet
        // if you press CTRL+C while the program is waiting, it won't exit immediately
        // its stuck waiting for a packet. This fixes it:
        let mut pckt = match queue.recv() {
            Ok(p) => p,
            Err(_) => continue, // ignore errors and try again
        };
        pckt.set_verdict(Verdict::Accept);
        pckt_count += 1;
        queue
            .verdict(pckt)
            .expect("[ERROR] Failed to push decision back to kernel.");

        print!("\rPackets: {}", pckt_count);
        std::io::stdout().flush().unwrap();
    }
}

struct IpTablesRedirector {
    que_num: u16,
}

impl IpTablesRedirector {
    pub fn new(num: u16) -> Self {
        let num_str = num.to_string();
        Command::new("iptables")
            .args(["-A", "INPUT", "-j", "NFQUEUE", "--queue-num", &num_str])
            .status()
            .expect("[ERROR] Failed to add iptables rule");
        println!("[INFO] IpTables rules added.");
        IpTablesRedirector { que_num: num }
    }
}

impl Drop for IpTablesRedirector {
    fn drop(&mut self) {
        let num_str = self.que_num.to_string();
        Command::new("iptables")
            .args(["-D", "INPUT", "-j", "NFQUEUE", "--queue-num", &num_str])
            .status()
            .expect("[ERROR] Failed to remove iptables rule");
        println!("[INFO] IpTables rules removed.");
    }
}
