# K-Crypt

## Overview

**K-Crypt** is a Python-based desktop application with a graphical user interface (GUI) that allows users to securely encrypt and decrypt files or entire folders using XOR cipher encryption. It combines simplicity with enhanced security by protecting the encryption key using AES-GCM encryption stored in a hidden `.dmrc` file.

Key features include:

* Encrypt/decrypt individual files or entire directories recursively.
* User-supplied encryption keys (no random keys unless user chooses).
* AES-GCM encrypted key storage in `.dmrc` file within the encrypted folder.
* Automatic preservation of original file timestamps.
* Drag-and-drop support (optional, requires `tkinterdnd2` package).
* User-friendly progress bar and log display.
* Menu-driven interface with file/folder browsing and mode selection.

---

## Prerequisites

* **Python 3.7+** (tested with Python 3.8+)
* Required Python packages:

  * `cryptography`
  * `tkinter` (usually included with Python, but may need separate install on Linux)
  * `tkinterdnd2` *(optional, for drag-and-drop support)*

### Installation of dependencies

```bash
pip install cryptography
pip install tkinterdnd2  # Optional for drag-and-drop support
```

On Debian/Ubuntu systems, you may need to install Tkinter separately:

```bash
sudo apt-get install python3-tk
```

---

## Installation

1. Clone or download this repository.

2. Ensure required Python packages are installed.

3. Run the main script:

```bash
python secure_xor_gui.py
```

---

## Usage Instructions

### Starting the Application

* Launch the GUI by running `secure_xor_gui.py`.

### Selecting Files or Folders

* Use the **File** menu to browse either a single file or a folder.
* Alternatively, use the **Browse** button next to the path entry field.
* Drag-and-drop file or folder paths into the path entry field (if `tkinterdnd2` is installed).

### Setting the Mode

* Choose between **Encrypt** or **Decrypt** via the **Mode** menu or radio buttons.

### Entering the Key

* Input your desired encryption/decryption key in the **Key** field.
* When decrypting, if the key field is left blank, the tool attempts to load the key automatically from the `.dmrc` file located inside the chosen folder.
* The `.dmrc` file is encrypted with a hardcoded AES-GCM key internal to the tool for security.

### Single File Mode

* Check **Single File Mode** if you want to operate on one file only.
* Leave unchecked to process entire folders recursively.

### Running Encryption or Decryption

* Click **Start** to begin processing.
* The progress bar shows operation status.
* The log window displays detailed per-file success or error messages.
* Upon successful encryption of folders, a `.dmrc` file with the encrypted key is saved in the folder.
* After successful decryption, the `.dmrc` key file is deleted automatically.

### Notes

* The tool preserves original file access and modification timestamps during encryption and decryption.
* Files already encrypted (recognized by a magic header) will not be re-encrypted.
* The tool only encrypts files with extensions (excluding the `.dmrc` file itself).
* If decrypting a folder, the tool processes all applicable files recursively.

---

## Security Considerations

* XOR cipher is a simple symmetric encryption method; security depends heavily on the secrecy and complexity of the key.
* The `.dmrc` file stores your key encrypted with a hardcoded AES-GCM key embedded in the tool binary. This is to protect the key at rest but assumes you have control over the tool's environment.
* Always keep your encryption keys safe and never share them.
* The tool does not currently support key rotation or multiple key versions.
* Do **not** use this tool for highly sensitive or classified data without further enhancements.

---

## Troubleshooting

* **Drag-and-drop not working?**
  Ensure `tkinterdnd2` is installed. If not installed, install via `pip install tkinterdnd2`, or ignore the warning and use manual browsing instead.

* **Tkinter not found or errors launching GUI?**
  Install Tkinter via your OS package manager (e.g., `sudo apt-get install python3-tk`) or ensure your Python installation includes it.

* **Permission errors when saving `.dmrc` file?**
  Run the tool with appropriate permissions to write to the target folder.

---

## License and Attribution

Author: KaotickJ
Version: 1.0
This tool is provided as-is without warranty. Use at your own risk.
