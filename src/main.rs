use nfq::{Queue, Verdict};
use std::process::Command;

fn main() {
    let nfqueue = 0;
    let _rules = IpTablesRedirector::new(nfqueue);
    // TO DO: Open Queue
    // TO DO: Accept All packets with Verdict
    // TO DO: Print the output with print!("");
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
