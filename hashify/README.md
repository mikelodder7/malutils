# Hashify

A command line tool that can create and verify checksums for multiple hash algorithms.

See [here for a video demo and explaination](https://youtu.be/67qoGRZApfY)

## The problem

When processing data, it is good practice to verify a checksum to check the data's integrity. Other terms include hash or digest. These are all aliases for the same thing
as far as the problem is concerned so checksum is used for the remainder of this explaination. Sometimes the type is stated like **md5**, **sha1**, or **sha256**. The issue is multiple executables
must be run to verify whether the checksums match. \*nix OS's have **md5sum**, **shasum**, **sha1sum**, **sha256sum**, **sha384sum**, **sha512sum** but it must be known which one to use.
In addition, the **shasum** tool family has many flags for processing the input and the checksum according to FIPS-180-4 but the output is restricted to lower case hex.
Windows doesn't have a command line tool handy to do so. PowerShell can run **Get-FileHash** but has limited algorithm selection,
and encoding fixed. Often, these tools do not state the endianess of the output.
Most use big endian, but regardless, the tool doesn't work at all if the byte ordering doesn't match. Administrators are left to fix the checksum byteorder separately.

## The solution
*Hashify* can verify any checksum with any encoding format either big or little endian. It also can run on any operating system.
This enables a system administrator to perform verifications quickly. The goal is to remove the guesswork from the administrator.

The flipside is creating checksums. *Hashify* can create any checksum and multiple of them to meet the administrator's needs in any encoding and byte order.

*Hashify* is written in Rust and has no external dependencies to do its job.

The program can be compiled from any OS to run on any OS.

## Run the program

*Hashify* can be run either using **cargo run -- \<args\>** or if it is already built from [source](#build-from-source)
using *./hashify*.

*Hashify* tries to determine if input is a file or text. If a file exists that matches the entered text, *Hashify* will
compute a checksum of the contents. Otherwise, it will compute a checksum on the provided text.


## Examples
*Hashify* can create a checksum from three sources: a file, text, or STDIN.

This command creates a checksum for a file name `python3`

```bash
hashify create /usr/bin/python3
```
the output looks like this
```
sha3-256      big-endian lowhex - da609c5456c6e72b7eec93d40ba7825ef1810540d7c62f2fbeb9a19931cf80c6
sha2-256      big-endian lowhex - 31f2aee4e71d21fbe5cf8b01ff0e069b9275f58929596ceb00d14d90e3e16cd6
sha2-512-t256 big-endian lowhex - ffd65fcb813c2b09c97c6583092a46530785c62ff35b31b0dbae3712964f6f88
blake2-256    big-endian lowhex - 97758ad2858cc7f17bc3ead1d8a744e7048759e0c2d6e20609e0e8702ff409a2
```
This just used the defaults which is to all 256 bit hash algorithms in big-endian and lower case hex encoding.
Its not necessary to produce multiple checksums, usually 1 is good enough or 2.
*Hashify* accepts 1 to as many checksums as needed using the **-t, --type** flags as comma separated values.
*Hashify* can also change the output encoding and endianess using the **-e, --encoding** and **-b, --byteorder** flags respectively.

*Hashify* was created to verify checksums and remove the guess work from an administrator.
Using the **sha2-256** checkum from the previous example, *Hashify* will try to guess the parameters used to generate the checksum
using the following command:

```bash
hashify verify 31f2aee4e71d21fbe5cf8b01ff0e069b9275f58929596ceb00d14d90e3e16cd6 /usr/bin/python3
```

which produces the output. Verification takes two inputs, a checksum and an input. The checksum can be a file or text; a file's contents will be read. Input can be a file, text, or STDIN. 

```
sha2-256      big-endian    hex    - pass
```

*Hashify* tries all algorithms that produce a 256 bit hash as hex encoding or 384 bit hash as base64 encoding.
If a match is found, it just list the winner. When no match can be found it outputs all failures as
```
sha2-256      little-endian hex    - fail
sha2-256      big-endian    base64 - fail
sha2-256      little-endian base64 - fail
sha2-512-t256 big-endian    hex    - fail
sha2-512-t256 little-endian hex    - fail
sha2-512-t256 big-endian    base64 - fail
sha2-512-t256 little-endian base64 - fail
blake2-256    big-endian    hex    - fail
blake2-256    little-endian hex    - fail
blake2-256    big-endian    base64 - fail
blake2-256    little-endian base64 - fail
sha3-256      big-endian    hex    - fail
sha3-256      little-endian hex    - fail
sha3-256      big-endian    base64 - fail
sha3-256      little-endian base64 - fail
sha2-384      big-endian    hex    - fail
sha2-384      little-endian hex    - fail
sha2-384      big-endian    base64 - fail
sha2-384      little-endian base64 - fail
sha3-384      big-endian    hex    - fail
sha3-384      little-endian hex    - fail
sha3-384      big-endian    base64 - fail
sha3-384      little-endian base64 - fail
blake2-384    big-endian    hex    - fail
blake2-384    little-endian hex    - fail
blake2-384    big-endian    base64 - fail
blake2-384    little-endian base64 - fail
```

If some of the parameters are known ahead of time, they can be passed to *Hashify* to save it some guesswork like

```bash
hashify verify --encoding=hex 31f2aee4e71d21fbe5cf8b01ff0e069b9275f58929596ceb00d14d90e3e16cd6 /usr/bin/python3
```

produces the following output
```
sha2-256      big-endian    hex - pass
```
and only had to try
```
sha2-256      little-endian hex - fail
sha2-512-t256 big-endian    hex - fail
sha2-512-t256 little-endian hex - fail
blake2-256    big-endian    hex - fail
blake2-256    little-endian hex - fail
sha3-256      big-endian    hex - fail
sha3-256      little-endian hex - fail
```

To see the tried algorithms, just add the **-v, --verbose** flag.

Create and Verify can be chained from other commands via the pipe operator because input can be read from STDIN like this

```bash
echo "My message to send out" | hashify create 
```

# NOTE:

Some of the algorithms are not considered cryptographically secure like md5 and ripemd128 are colored red to indicate it shouldn't be used for high secure contexts.
sha1 has been broken but the attack is not considered practical yet and thus is colored yellow to indicate it shouldn't be used but is still okay for now for legacy purposes.
ripemd160 and ripemd320 should also not be used except for legacy purposes.

# Options
The following hash algorithm types **-t, --type** are currently supported:

- md5
- sha1
- sha2-224
- sha2-256
- sha2-384
- sha2-512
- sha2-512-t224
- sha2-512-t256
- sha3-224
- sha3-256
- sha3-384
- sha3-512
- blake2-256
- blake2-384
- blake2-512
- whirpool
- ripemd128
- ripemd160
- ripemd320

The following encoding options **-e, --encoding** are currently supported:

- blob    (raw bytes)
- binary  (0b101010101)
- base10  (0-9)
- lowhex  (0-9a-f)
- uphex   (0-9A-F)
- base58  (Bitcoin Base58 no check)
- base64
- base64-url

## Results

I have timed *Hashify* against **shasum**, **sha256sum**, and many others. For small files it won't be noticeable, 
but for large files like ISO images, it typically runs 0.5 secs faster per GB.

## Build from source
[build-from-source]: # build-from-source

To make a distributable executable, run the following commands:

1. **curl https://sh.rustup.rs -sSf | sh -s -- -y** - installs the run compiler
1. **git clone https://gitlab.com/mikelodder7/csc842.git**
1. **cd csc842/Module1**
1. **cargo build --release** - when this is finished the executable is *target/release/hashify*.
1. For \*nix users **cp target/release/hashify /usr/local/lib** and **chmod +x /usr/local/lib/hashify**
1. For Windows users copy **target/release/hashify** to a folder and add that folder to your %PATH variable.
