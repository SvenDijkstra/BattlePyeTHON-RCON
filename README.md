# BattlePyeRCON

A Python-based Battle Eye RCON tool for Linux, primarily designed for Arma Reforger.

**Please Note:** This tool is currently in a poorly functioning state and requires significant cleanup, checks, and improvements.  Specifically, connection timeout and disconnect handling are broken. Use with caution.

## Purpose

This tool provides command-line access to the Battle Eye RCON interface, enabling server administrators to manage their Arma Reforger servers from a Linux environment.  Existing RCON tools are often Windows-centric, and this project aims to bridge that gap.

## Features (As-Is)

* Basic RCON connectivity.
* Command-line interface.

## Limitations (Major - Requires Attention)

* **Broken Connection Timeout:** The connection timeout mechanism is not working as expected.
* **Broken Disconnect Handler:** The disconnect handler is faulty.
* Poor/Unreliable Performance: The tool is described as "very poorly" functioning.
* Lack of input validation and error handling.
* Likely lacks more robust features.

## Installation

The following dependencies are required:

* Python 3
* `pip` (Python package installer)
* `python3-crc32c`

Installation steps:

1.  Install Python 3:

    ```
    sudo apt install python3
    ```

2.  Install `pip`:

    ```
    sudo apt install python3-pip
    ```

3.  Install `python3-crc32c`:

    ```
    sudo apt install python3-crc32c
    ```

    \* As per the search results, you might also be able to install it using `pip install crc32c`.

4.  (Optional) It's generally good practice to use a virtual environment:

    ```
    python3 -m venv .venv #creates a virtual environment in a folder called .venv
    source .venv/bin/activate #activates the virtual environment
    ```

5.  Install the python dependencies:

    ```
    pip install argparse cmd configparser #These are in the standard library, but pip will ensure they are present.
    pip install crc32c # This was already installed via apt, but doing it again with pip is usually harmless and good practice in a venv.
    pip install readline #This is also in the standard library, but pip will ensure it is present.
    ```

## Usage

The tool is a command-line script that requires the following arguments:

* `-H` or `--host`:  The RCON IP address.
* `-p` or `--port`:  The RCON port number (integer).
* `-P` or `--password`: The RCON password (string).

**Example:**

./BattlePyeRCON.py -H 10.0.0.1 -p 20002 -P 1N5eCur3P4$$w0Rd!
## Troubleshooting

To troubleshoot network connectivity issues, you can use the following `tcpdump` command.  This command corresponds to the parameter variables used in the Usage example:

sudo tcpdump -i any udp port 20002 -vv -X
This command will capture and display UDP packets on port 20002, showing detailed information (`-vv`) and the packet contents in both hexadecimal and ASCII formats (`-X`).  Adjust the port number as needed to match your Arma Reforger RCON port.

## Imports

The script uses the following Python modules:

import argparseimport cmdimport configparserimport crc32cimport loggingimport osimport readlineimport socketimport structimport sysimport timeimport threading
## Contributing

Contributions are welcome, especially to address the known issues and improve the tool's reliability.  Areas for improvement include:

* Fixing the connection timeout.
* Correcting the disconnect handler.
* Adding input validation for the command-line arguments.
* Implementing proper error handling.
* Adding more RCON commands.
* Improving the overall code structure and robustness.
* Adding a configuration file.
* Adding a reconnection mechanism.
* Adding multithreading.
