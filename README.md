# Brute Cracker

This is a brute-force password cracker written in pure C with a built-in MD5 implementation.  
It is designed to test how secure a given password is by trying all possible combinations of lowercase letters until the MD5 hash matches.

This project is for educational and demonstrational purposes only.

---

## 🚀 Features

- Brute-force generator using recursive search
- Pure C implementation, no external libraries required
- Custom MD5 hashing (no OpenSSL needed)
- Detects password by matching MD5 hash
- Graceful interruption via `CTRL+C`
- Clear progress feedback every million attempts

---

## 🧪 How it works

1. You input a password (e.g. `abc`)
2. The program computes its MD5 hash
3. Then it brute-forces all possible combinations of characters (`a`, `aa`, `ab`, `zz...`) starting from length 1
4. When it finds a match, it shows the password, number of attempts, and total time

---

## 💻 Build instructions

No external libraries are needed.

### 🔧 Compile with GCC:
```bash
gcc -O3 brute_cracker.c -o brute_cracker
