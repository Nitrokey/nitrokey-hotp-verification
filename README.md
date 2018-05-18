# Nitrokey HOTP verification tool

Nitrokey [HOTP](https://tools.ietf.org/html/rfc4226) verification tool is a command line application, which communicates with a custom Nitrokey (over HIDAPI/libusb) to configure HOTP secrets and to verify HOTP codes. The Nitrokey being used needs to support HOTP verification, which is - at the time of writing - supported by a custom firmware for Nitrokey Pro.

This solution is meant to allow users to verify the authenticity of his computer. During the boot process of the computer, the user will be asked to insert his Nitrokey device, which verifies the HOTP code generated and sent by the computer. The Nitrokey indicates the verification result by LED: success = green LED blinking; failure = red LED blinking quicker.


## Requirements
This tool uses [HIDAPI](https://github.com/Nitrokey/hidapi) library to communicate with the Nitrokey device. It is a light wrapper over the `libusb` API and requires `usb-1.0` library at the link time.

This tool also reads from `/dev/urandom` to generate session secret for device-authorization purposes.

The Nitrokey device needs to support HOTP verification.

## Compilation
This tool uses CMake for compilation. Please run:

```bash
mkdir build && cd build
cmake .. && make
```
To list compilation options please use:
```bash
$ cmake -LH ..
-- Configuring done
-- Generating done
-- Build files have been written to: /home/sz/work/nitrokey-hotp-verification/build-clang
-- Cache values
// Add information about source code version from Git repository
ADD_GIT_INFO:BOOL=ON

// Choose the type of build, options are: None(CMAKE_CXX_FLAGS or CMAKE_C_FLAGS used) Debug Release RelWithDebInfo MinSizeRel.
CMAKE_BUILD_TYPE:STRING=Debug

// Install path prefix, prepended onto install directories.
CMAKE_INSTALL_PREFIX:PATH=/usr/local

// Link application against system HIDAPI library
USE_SYSTEM_HIDAPI:BOOL=OFF

```
Example compilation flags use:
```bash
cmake .. -DADD_GIT_INFO=OFF -DCMAKE_BUILD_TYPE=Release
```

## Usage
Before each device-related command a connection attempt will be done. If the Nitrokey Pro will not be detected immediately, the tool will monit for its insertion and will wait for 40 seconds (probing each 0.5s), quitting if connection would not be possible.
  
#### Setting HOTP secret
To set a new HOTP secret to be verified on the device please run:
```bash
./nitrokey_hotp_verification set <BASE32 HOTP SECRET> <ADMIN PIN>
```
where:
- `<BASE32 HOTP SECRET>` is a new base32 HOTP secret, with up to 160 bits of length
- `<ADMIN PIN>` is a current Admin PIN of the Nitrokey Pro device
#### Verifying HOTP code
To verify the HOTP code please run `check` command as in:
```bash
./nitrokey_hotp_verification check <HOTP CODE>
```
where:
`<HOTP CODE>` is a 6-digits HOTP code to verify

In case where the code is verified on the device, the green LED will blink 5 times. Otherwise the red LED will blink 5 times, twice as fast than green.

Verification of 8-digits codes is available as an option through build configuration in [settings.h](settings.h). Responsible flag is configured on device during the HOTP secret setup phase and cannot be changed (until another secret rewrite) in the current implementation.

Solution contains a mean to avoid desynchronization between the host's and device's counters.
Device calculates up to 9 values ahead of its current counter to find the matching code (in total it calculates HOTP code for 10 subsequent counter positions). In case:
- no code would match - the on-device counter will not be changed;
- code would match, but with some counter's offset (up to 9) - the on-device counter will be set to matched code-generated HOTP counter and incremented by 1;
- code would match, and the code matches counter without offset - the counter will be incremented by 1.

Device will stop verifying the HOTP codes in case, when the difference between the host and on-device counters will be greater or equal to 10.

#### Identifying the device
To show information about the connected device please use:
```bash
$ ./nitrokey_hotp_verification info
# which results should be similar to:
HOTP code verification application via Nitrokey Pro
Connected device status:
 Card serial: 0x5F11
 Firmware: v0.9
 Card counters: Admin 3, User 3
```
To show only the card's serial please run:
```bash
$ ./nitrokey_hotp_verification id
```
#### Complete example
```bash
# set 160-bit secret with RFC's test secret "12345678901234567890"
./nitrokey_hotp_verification set GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ 12345678
./nitrokey_hotp_verification check 755224
./nitrokey_hotp_verification check 287082
./nitrokey_hotp_verification check 359152

# show response to a wrong code
./nitrokey_hotp_verification check 111111

```

#### Help screen
```bash
HOTP code verification application via Nitrokey Pro, version 1.0-alpha
Available commands:
 ./nitrokey_hotp_verification id
 ./nitrokey_hotp_verification info
 ./nitrokey_hotp_verification version
 ./nitrokey_hotp_verification check <HOTP CODE>
 ./nitrokey_hotp_verification set <BASE32 HOTP SECRET> <ADMIN PIN>

```

#### Exit codes
In case the tool would encounter any critical issues, it will print error message and return to the OS with a proper exit code value. Meaning of the exit values could be checked with the following table: 

Error code name | Exit code | Meaning
--- | :---: | ---
EXIT_NO_ERROR | 0 | Operation was completed successfully or HOTP code was confirmed to be valid
EXIT_CONNECTION_ERROR | 1 | Could not connect to the Nitrokey Pro device
EXIT_WRONG_PIN | 2 | Could not authorize the user with the user given PIN
EXIT_OTHER_ERROR | 3 | Unknown error
EXIT_INVALID_HOTP_CODE | 4 | Entered HOTP code was calculated to be invalid
EXIT_UNKNOWN_COMMAND | 5 | Device does not support HOTP verification command in this firmware
EXIT_SLOT_NOT_PROGRAMMED | 6 | On-device slot was not programmed with HOTP secret yet
EXIT_BAD_FORMAT | 7 | Either entered HOTP code for validation or base32 secret to set was in improper format (too long or consisting of invalid characters)
  EXIT_CONNECTION_LOST | 8 | Connection to the device was lost during the process
EXIT_INVALID_PARAMS | 100 | Application could not parse command line arguments

## Tests
Solution was tested against 160-bits test vectors available at [RFC_HOTP-test-vectors.txt](RFC_HOTP-test-vectors.txt). 

#### Environment
- Ubuntu 18.04
- gcc (Ubuntu 7.3.0-16ubuntu3) 7.3.0
- libusb-1.0 package version: 2:1.0.21-2
- CMake 3.10.2

Code analysers:
- Valgrind-3.13.0
- Cppcheck 1.82
- Clang tools package version: 1:5.0.1-4

#### Code correctness
Code was tested against Valgrind, Clang static checker (scan-build) and Cppcheck. Compilation is run with all warnings enabled (flags `-Wall -Wextra`).

#### Unit tests
With `-DCOMPILE_TESTS=TRUE` compilation switch it is possible to compile tests, which are checking the solution against RFC specification. Details are available at [tests/test_hotp.cpp](tests/test_hotp.cpp). To run them please issue:
```bash
./test_hotp
```
Tests could be run selectively - see `--help` switch to learn more.

**Warning:** before running the tests please make sure to use a not production device to avoid important data removal. Tests use default Admin PIN: `12345678`. 

#### Size
In a Release build, with statically linked HIDAPI, application takes 50kB of storage (42kB stripped).

## License
Code is licensed under GPLv3, excluding `base32.{h,c}` files. The latter are downloaded from [tpmtopt](https://github.com/osresearch/tpmtotp) project and seem to be licensed under [MIT](https://choosealicense.com/licenses/mit/) license.