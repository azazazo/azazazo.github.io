+++
title = "IrisCTF 2025 writeups"
date = "2025-01-06T18:06:12+08:00"
author = "azazo"
description = "First CTF of the year wow"
tags = ["ctf", "writeup"]
showFullContent = false
readingTime = false
hideComments = false
+++

{{< math >}}

I played in IrisCTF 2025 as part of Untitled CTF Game, and got 34th place in the end. We were ahead of NUS Greycats at one point though :)

I liked the challenges from this CTF, and managed to solve three crypto, one misc, one rev and one pwn challenge in the end. However, I'll only be writing about the three challenges that did not get point decayed to 50 points.

# Misc - O_WRONLY
> I used the proprietary michaelsec tool to protect my secret data. Can you recover it?

Despite being tagged with `#kernel` this challenge was fortunately not a pwn one, as the `README.md` kindly pointed out. The flag is stored in `/dev/vda`, but naïvely trying to read it gives us a strange message.

```bash
~ $ cat /dev/vda
Permission Denied
```

What a shame. I didn't particularly feel like reading the source code of the kernel device, so I just tried using a symlink, and it miraculously worked:

```bash
~ $ ln -s /dev/vda test
ln -s /dev/vda test
~ $ cat test
cat test
irisctf{michaelsec_secure_file_protection}
```

Oh well. I can't really tell if this was the intended solution, especially since there seems to be more complicated things going on in the kernel device source code, but a flag is a flag.

Flag: `irisctf{michaelsec_secure_file_protection}`

# Crypto - Knutsacque
> Behold my original knut sacque scheme in 4D

ha ha. nut sack
```py
import secrets

F.<i,j,k> = QuaternionAlgebra(-1, -1)
A = []
B = [1, i, j, k]

msg_bin = b"irisctf{redacted_redacted_redacted_}"
assert len(msg_bin) % 4 == 0
msg = [F(sum(Integer(msg_bin[idx+bi])*b for bi, b in enumerate(B))) for idx in range(0, len(msg_bin), len(B))]
targ = 2^64

for _ in range(len(msg)):
    a = F(sum(secrets.randbelow(targ)*b for b in B))
    A.append(a)

sm = F(0)
for idx in range(len(msg)):
    sm += msg[idx] * A[idx]

print("A =", A)
print("s =", sm)
```

This challenge generates quaternions from the flag four characters at a time (which we will represent as \(x_i\)), multiplies each of them by a randomly generated quaternion \(A_i\), then returns the sum \(s\).

We can first notice that because of how quaternion multiplication works, the coefficients of \(s\) are sums of products of the coefficients of \(x_i\) and the coefficients of \(A_i\). Furthermore, we have that \(x_i \ll A_i\). Sounds like a perfect setup for a lattice-based approach.

Because quaternions are painful to work with, we can represent them as matrices instead with the isomorphism

\[
    a + b\mathbf{i} + c\mathbf{j} + d\mathbf{k} \mapsto
    \begin{bmatrix}
        a & b & c & d\\
        -b & a & -d & c\\
        -c & d & a & -b\\
        -d & -c & b & a
    \end{bmatrix}
\]

Since we have 9 elements in `A`, and each quaternion is formed from 4 characters, we know that the flag has length 36. We can write a quick script to see the matrix representation of \(s\), and verify that its entries are indeed formed with linear combinations of flag characters \(f_i\).

{{< image src="/images/irisctf25/ew.png" position="center">}}

Now, we have 4 linear simultaneous equations with \(f_i\). Normally this would not guarantee us a unique solution, but since \(0 < f_i < 255\) with LLL we have good chances of finding a solution. Our initial lattice basis in \(\mathbb{Z}^{37\times53}\) looks like this

\[
    \begin{bmatrix}
        1000\mathbf{C} & \mathbf{I_{36}} & \mathbf{0}\\
        1000\mathbf{S} & \mathbf{0} & 100
    \end{bmatrix}
\]

where \(\mathbf{C} \in \mathbb{Z}^{36\times16}\) represent the coefficients of the linear equations and \(\mathbf{S} \in \mathbb{Z}^{1\times16}\) represent the entries of the matrix representation of \(s\). 1000 and 100 are just arbitrary constants to "balance" out the solution we want, increasing the odds of the solution appearing in the LLL reduced basis. We would expect the solution in the reduced basis to look something like

\[
    \begin{bmatrix}
        0 & \dots & 0 & f_0 & f_1 & \dots & f_{35} & 100
    \end{bmatrix}
\]

with 16 zeroes before the flag characters. Sure enough, when we look through the reduced basis, we find something similar:

{{< image src="/images/irisctf25/reduced.png" position="center">}}

Negating the vector and extracting the entries in the middle, we get our flag :)

Full solve script:
```py
F.<i,j,k> = QuaternionAlgebra(-1, -1)
A = []
B = [1, i, j, k]

A = [17182433425281628234 + 14279655808574179137*i + 8531159707880760053*j + 10324521189909330699*k, 10979190813462137563 + 11958433776450130274*i + 10360430094019091456*j + 11669398524919455091*k, 3230073756301653559 + 4778309388978960703*i + 7991444794442975980*j + 11596790291939515343*k, 11946083696500480600 + 18097491527846518653*i + 5640046632870036155*j + 2308502738741771335*k, 12639949829592355838 + 12578487825594881151*i + 5989294895593982847*j + 9055819202108394307*k, 15962426286361116943 + 6558955524158439283*i + 2284893063407554440*j + 14331331998172190719*k, 14588723113888416852 + 432503514368407804*i + 11024468666631962695*j + 10056344423714511721*k, 2058233428417594677 + 7708470259314925062*i + 7418836888786246673*j + 14461629396829662899*k, 4259431518253064343 + 9872607911298470259*i + 16758451559955816076*j + 16552476455431860146*k]

s = -17021892191322790357078 + 19986226329660045481112*i + 15643261273292061217693*j + 21139791497063095405696*k

def tomatrix(a, b, c, d):
    return matrix([
        [a, b, c, d],
        [-b, a, -d, c],
        [-c, d, a, -b],
        [-d, -c, b, a]
    ])

f = var(" ".join([f"f{i}" for i in range(36)]))

S = sum([tomatrix(f[4*i], f[4*i+1], f[4*i+2], f[4*i+3])*A[i].matrix() for i in range(9)]).list()

m = matrix(ZZ, 36+1, 16+36+1)
m[-1] = (1000*s).matrix().list() + [0 for _ in range(36)] + [100]
for j, x in enumerate(S):
    for i in range(36):
        m[i, j] = 1000*x.coefficient(f[i])
for i in range(36):
    m[i, i+16] = 1

L = m.LLL()

sol = -L[-5] # from visual inspection
print("".join(map(chr, sol[16:16+36])))
```

Flag: `irisctf{wow_i_cant_believe_its_lll!}`

# Crypto - AYES
> Something is a bit off with my AES implementation. Get it?
>
> AES implementation is directly from [here](https://github.com/boppreh/aes).

```py
import aes
import secrets

print("Oh no! I dropped a bit. Where was it again...?")
bit = int(input("> "))

bits = list(bin(int.from_bytes(bytes(aes.s_box), "big"))[2:].rjust(256 * 8, '0'))
bits[bit] = "1" if bits[bit] == "0" else "0"
aes.s_box = int(''.join(bits), 2).to_bytes(256, "big")

print("Got it, thanks! Have some encryptions, as a gift.")

key = secrets.token_bytes(16)
a = aes.AES(key)
for _ in range(2**12):
    encrypted = a.encrypt_block(bytes.fromhex(input("> ")))
    print(encrypted.hex())

    if encrypted == key:
        print("Really? I guess you've earned this.")
        with open("/flag") as f:
            print(f.read())

print("Why are we still here?")
```

When I first saw this challenge, I thought I would (finally) have to learn cryptanalysis, and was a bit daunted. However, it turned out to be quite easy.

We are given an implementation of AES, with the quirk we must flip one of the bits of the numbers in the s-box. Then, we are given \(2^12 = 4096\) chances to encrypt some plaintext, and we must submit something that when encrypted results in the key. Effectively, we would have to recover the key used.

The AES algorithm being executed looks something like this (apologies for the lack of pseudocode skill):
```bash
AddRoundKey()
for i in 1..9 do
    SubstituteBytes()
    ShiftRows()
    MixColumns()
    AddRoundKey()
done
SubstituteBytes()
ShiftRows()
AddRoundKey()
```
where the 16 byte long round keys are derived from the "master" key with the key scheduling algorithm. As we can change one bit in the s-box, we can affect the workings of `SubstituteBytes()`.

We can notice that if we change one bit of the s-box, it will no longer be bijective; that is, one byte will no longer be able to be the result of substitution. Let's call this byte \(b\). To see what this means in practice, let's zoom in on the last "round" of the AES algorithm.

```
...
SubstituteBytes()
ShiftRows()
AddRoundKey()
```

We know that the output of `SubstituteBytes()` will never contain \(b\). Since `ShiftRows()` simply permutes the bytes and `AddRoundKey()` performs XOR byte by byte, if we represent the ciphertext by \(c_i\) and the final round key by \(k_i\) we have that

\[
    \begin{align}
    c_i \oplus k_i &\ne b\\
    k_i &\ne b \oplus c_i
    \end{align}
\]

Since we know the value of \(b\), this means that we can slowly eliminate possibilities for \(k_i\) byte by byte with each ciphertext we obtain until we only have one possibility for each \(k_i\), and recover the final round key. From my testing this takes anywhere from between 1500 to 2500 ciphertexts (about 8 minutes of interaction with the server), but since we are allowed to query 4096 times we should be able to recover it with queries to spare.

With the final round key, we can reverse the key scheduling algorithm to obtain the "master" key, and use it to decrypt itself to satisfy the requirements of the challenge. In theory, just running the inverse key scheduling algorithm and decryption algorithm should not work as the s-box has changed, but somehow it worked. I'm not too sure why this is the case, but I will think about it and update writeup when I find out.

**Update**: I reran my solve script a few more times, and it looks like you don't consistently get the flag (it failed 3 out of 10 times). I guess the changed s-box thing still applies, and I was just lucky.

Full solve script:
```py
import aes
from os import urandom
from pwn import *
from tqdm.auto import tqdm

aes.s_box = ( # change first element from 0x63 to 0xE3
    0xE3, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

io = remote("ayes.chal.irisc.tf", 10100)
io.sendlineafter(b"> ", b"0")

def query(n):
    io.sendlineafter(b"> ", n.hex().encode())
    return bytes.fromhex(io.recvline().strip().decode())

lastrk = {i: list(range(256)) for i in range(16)}
for _ in tqdm(range(4096)):
    not_rkey = aes.xor_bytes(query(urandom(16)), b"\x63"*16)
    for p,x in enumerate(not_rkey):
        if x not in lastrk[p]:
            continue
        lastrk[p].remove(x)
    if all(len(i) == 1 for i in lastrk.values()): break

print(f"Last round key: {lastrk}")
key = [lastrk[i][0] for i in range(16)]

def get_prev_rkey(rkey, rcon_index):
    prev = []
    for i in range(15, 3, -1):
        prev = [rkey[i] ^ rkey[i-4]] + prev
    x = [aes.s_box[i] for i in prev[-3:] + [prev[-4]]]
    x[0] ^= aes.r_con[rcon_index]
    prev = list(aes.xor_bytes(x, rkey[:4])) + prev
    return prev

for i in range(10, 0, -1):
    key = get_prev_rkey(key, i)
key = bytes(key)

print(f"Master key: {key}")

plain = aes.AES(bytes(key)).decrypt_block(bytes(key)).hex()
io.sendline(plain.encode())
io.interactive()
```

Flag: `irisctf{the_first_round_really_is_the_key}`