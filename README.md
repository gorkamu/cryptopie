# 🍰🍰 Crypto Pie

This is a software to encrypt/decrypt files or entire directories with support for several types of algorithms.

## How to install it

First of all you have to clone the repository
```
git clone git@gitlab.com:gorkamu/cryptopie.git
```

Then go to the cloned folder and type the following command:
```
pip install -r requeriments.txt
```

If this fails you can install manually the dependencies with this command:
```
pip install cryptography
```

## How to use it
```
usage: cryptopie.py [-h] -p PATH [-k KEY] [-e] [-d] [-a ALGORITHM]

optional arguments:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  define the file or directory path to encrypt/decrypt
  -k KEY, --key KEY     key to encrypt/decrypt
  -e, --encrypt         encrypt the file or directory
  -d, --decrypt         decrypt the file or directory
  -a ALGORITHM, --algorithm ALGORITHM
                        encryption algorithm: [SHA224|SHA256|SHA384|SHA512|SHA
                        512_224|SHA512_256|BLAKE2b|BLAKE2s|SHA3_224|SHA3_256|S
                        HA3_384|SHA3_512|SHAKE128|SHAKE256|SHA1|MD5]
```

![Crypto Pie](https://i.imgur.com/iVbN40w.png)

If you want to encrypt a file or a directory structure just type the command:
```
python cryptopie.py -p PATH -e -a SHA256
```

The -a argument is optional and it indicates the algorithm to be used. If you don't specify it, it will be used the SHA256 algorithm by default

Once you have encrypted a file/directory if you want to decrypt it just have to type the following command:
```
python cryptopie.py -p PATH -d -k ENCRYPTION_KEY
```

### Supported encryption algorithms
- SHA224
- SHA256
- SHA384
- SHA512
- SHA512_224
- SHA512_256
- BLAKE2b
- BLAKE2s
- SHA3_224
- SHA3_256
- SHA3_384
- SHA3_512
- SHAKE128
- SHAKE256
- SHA1
- MD5