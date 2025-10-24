# 🧾 Changelog

## [2.1.0] - 2025-10-24
### 🆕 Added
- **Automatic Port Prompt:**  
  When a target (`-t` / `--target`) is provided without `--ports`, the scanner now interactively asks for ports to scan.  
  This allows easy entry of ranges (e.g., `20-25`) or comma-separated lists (e.g., `80,443`).

- **Interactive Fallback Mode:**  
  Even in non-interactive runs, the tool switches to prompting for ports if none were given.

- **Graceful Keyboard Interrupt Handling:**  
  Pressing `Ctrl+C` while entering ports or during scans now exits cleanly with a message.

### 🛠️ Fixed
- **Port Range Parsing Bug:**  
  `argparse` previously misinterpreted `-p 20-25` as a flag (`-25`), breaking range scanning.  
  The new prompt system avoids this and ensures ranges work correctly.

- **Optional `--ports` Argument:**  
  The `--ports` parameter is now optional, resolving issues when only `--target` was specified.

### 💡 Improved
- Enhanced usability in both interactive and non-interactive modes.
- Better user experience for mixed TCP/UDP scans.
- Clean and consistent exit messages on interrupts.

---

## [2.0.0] - Original Release
### 🚀 Features
- Asynchronous TCP and UDP port scanning.
- Concurrent scanning with configurable timeout and concurrency.
- IPv4 and IPv6 resolution.
- Interactive and command-line modes.
- Colorized terminal output using **colorama**.

---

## 🔧 Usage Examples

### Interactive Mode
```bash
python lunaportscanner.py
