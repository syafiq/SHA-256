# ==================
# SHA-256
# Syafiq Al Atiiq
# atiiq@kth.se
# ==================

import sys
import struct

from sys import stdin

# This code is the implementation of SHA256 from the pseudocode from wikipedia
# https://en.wikipedia.org/wiki/SHA-2#Pseudocode

# var

# Initialize hash values
# (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
h_val = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

# Initialize array of round constants:
# (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
k_val = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

# pre-processing

# append the bit '1' to the message
# append k bits '0', where k is the minimum number >= 0 such that the resulting message length (modulo 512 in bits) is 448.
# append length of message (without the '1' bit or padding), in bits, as 64-bit big-endian integer
# (this will make the entire post-processed length a multiple of 512 bits)

def pad_m(m):
    """
    padding message m by the rules of pre-processing above
    """
    # print m.encode('hex_codec')
    # current len
    mlen = len(m)
    # print mlen
    # append 1 -> "80"
    m += "80".decode('hex_codec')
    # print m.encode('hex_codec')
    # divide the whole len by 64, and find the closest rounding off 
    b = (mlen + 1 + 8 + (64-1)) // 64
    # print b
    len_req = 64*b
    # print len_req
    pad_len = len_req - mlen - 1 - 8

    # append 0 -> "00"
    m += pad_len*"00".decode('hex_codec')
    # debugp(m)
    m += ("%016X" % (mlen*8)).decode('hex_codec')
    # debugp(m)
    return m

def debugp(m):
    """
    just for debugging and make life easier
    """
    print m.encode('hex_codec')

def rightrotate(a,b):
    return ((a >> b) | (a << (32-b))) & 0xFFFFFFFF

def rightshift(a,b):
    return a >> b

# Hash Function
def hash(m):
    # pre processing
    m = pad_m(m)
    # debugp(m)

    h = list(h_val)
    k = list(k_val)

    # Process the message in successive 512-bit chunks:
    # (The initial values in w[0..63] don't matter, so many implementations zero them here)
    # Split m into blocks
    # split into 64
    blocks_1 = []
    for i in range(0, len(m), 64):
        blocks_1.append(m[i:i+64])
    
    #debugp(blocks[1])
    # split into 4 
    for blocks_2 in blocks_1:
        w = []
        for i in range(0, len(blocks_2), 4):
            s = struct.unpack(">I", blocks_2[i:i+4])
            #debugp(s[0])
            # append first one
            # copy chunk into first 16 words w[0..15] of the message schedule array
            w.append(s[0])

        # Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
        for i in range(16,64):
            s0_1 = rightrotate(w[i-15], 7) ^ rightrotate(w[i-15], 18) ^ rightshift(w[i-15], 3)
            s0 = rightrotate((w[i-15]),7)
            s1_1 = rightrotate(w[i-2], 17) ^ rightrotate(w[i-2], 19) ^ rightshift(w[i-2], 10)
            w.append(( w[i-16] + s0_1 + w[i-7] + s1_1 ) & 0xFFFFFFFF)

        # Initialize working variables to current hash value:
        a_var = h[0]
        b_var = h[1]
        c_var = h[2] 
        d_var = h[3]
        e_var = h[4]
        f_var = h[5]
        g_var = h[6]
        h_var = h[7]

        # Compression function main loop:
        for i in range(64):
            s1_2 = rightrotate(e_var, 6) ^ rightrotate(e_var, 11) ^ rightrotate(e_var, 25)
            ch = (e_var & f_var) ^ ((0xFFFFFFFF^e_var) & g_var)
            tmp1 = (h_var + s1_2 + ch + k[i] + w[i]) & 0xFFFFFFFF
            s0_2 = rightrotate(a_var, 2) ^ rightrotate(a_var, 13) ^ rightrotate(a_var, 22)
            maj = (a_var & b_var) ^ (a_var & c_var) ^ (b_var & c_var)
            tmp2 = (s0_2 + maj) & 0xFFFFFFFF

            h_var = g_var
            g_var = f_var
            f_var = e_var
            e_var = (d_var + tmp1) & 0xFFFFFFFF
            d_var = c_var
            c_var = b_var
            b_var = a_var
            a_var = (tmp1 + tmp2) & 0xFFFFFFFF

        # Add the compressed chunk to the current hash value:
        h[0] += a_var
        h[1] += b_var
        h[2] += c_var
        h[3] += d_var
        h[4] += e_var
        h[5] += f_var
        h[6] += g_var
        h[7] += h_var
        
        h_len = len(h)
        for j in range(h_len):
            h[j] = h[j] & 0xFFFFFFFF
    
    # Produce the final hash value (big-endian):
    # digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7

    output = ""
    for h_var in h:
        output += struct.pack(">I", h_var)

    return output
            
# main 
if __name__ == "__main__":
    for line in sys.stdin:
        line = line.strip().decode('hex_codec')
        # print line
        output = hash(line)
        print output.encode('hex_codec')