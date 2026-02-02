# Rust Packet Counter

A high-performance packet counter written in Rust that intercepts traffic using Linux Netfilter Queues (NFQUEUE).

This project demonstrates how to interface Rust with the Linux kernel, manage `iptables` rules programmatically, and safely handle system signals (Ctrl+C).

# How to Run

Because this program interacts with kernel queues and firewalls, it requires root privileges. However, cargo should be run as your normal user.

  1. Build the project (as normal user):
  
  ```bash
  cargo build
  ```

  2. Run the binary (as root):

  ```bash
  sudo ./target/debug/packet_counter
  ```
