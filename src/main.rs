use nfq::{Queue, Verdict};
use std::io::Write;
use std::process::Command; // needed this for flush the buffer

fn main() {
    let nfq_num = 0;
    let _rules = IpTablesRedirector::new(nfq_num);
    let mut pckt_count: u64 = 0;
    let mut queue = Queue::open().expect("[ERROR] Failed to open NFQUEUE");
    queue
        .bind(nfq_num)
        .expect("[ERROR] Failed to bind to queue");
    loop {
        let mut pckt = queue.recv().expect("[ERROR] Failed to read packet.");
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
