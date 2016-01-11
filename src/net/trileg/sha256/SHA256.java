package net.trileg.sha256;

public class SHA256 {
  private int[] H = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  private int[] K = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};


  public void outputByteArray(String text, byte[] input) {
    System.out.print(String.format(text + ": len=%d, ", input.length));
    for (byte i : input) {
      System.out.print(String.format("%02x ", i));
    }
    System.out.println();
  }

  private String hexString(int input) {
    byte[] tmp = new byte[4];
    tmp[0] = (byte) (input >>> 24);
    tmp[1] = (byte) (input >>> 16);
    tmp[2] = (byte) (input >>> 8);
    tmp[3] = (byte) (input);
    return hexString(tmp);
  }

  private String hexString(byte[] input) {
    final String hexChar = "0123456789ABCDEF";

    StringBuilder stringBuilder = new StringBuilder();
    for (byte i : input) {
      stringBuilder.append(hexChar.charAt((i >> 4) & 0x0F));
      stringBuilder.append(hexChar.charAt(i & 0x0F));
    }

    return stringBuilder.toString();
  }


  private byte[] getLengthArray(long len) {
    byte[] tmp = new byte[8];
    tmp[0] = (byte) (len >> 56);
    tmp[1] = (byte) (len >> 48);
    tmp[2] = (byte) (len >> 40);
    tmp[3] = (byte) (len >> 32);
    tmp[4] = (byte) (len >> 24);
    tmp[5] = (byte) (len >> 16);
    tmp[6] = (byte) (len >> 8);
    tmp[7] = (byte) (len);
    return tmp;
  }

  public byte[] padding(byte[] message) {
    int original_byte_len = message.length;
    long original_bit_len = original_byte_len * 8;

    byte[] append_one = new byte[original_byte_len + 1];
    System.arraycopy(message, 0, append_one, 0, original_byte_len);
    append_one[append_one.length - 1] = (byte) 0x80;
    int append_one_bit_length = append_one.length * 8;

    while (append_one_bit_length % 512 != 448) {
      append_one_bit_length += 8;
    }

    byte[] append_zeros = new byte[append_one_bit_length / 8];
    System.arraycopy(append_one, 0, append_zeros, 0, append_one.length);

    for (int i = append_zeros.length - 1; i > append_one.length - 1; i--) {
      append_zeros[i] = (byte) 0x00;
    }

    byte[] lengthArray = getLengthArray(original_bit_len);
    byte[] padded = new byte[append_zeros.length + lengthArray.length];
    System.arraycopy(append_zeros, 0, padded, 0, append_zeros.length);
    System.arraycopy(lengthArray, 0, padded, append_zeros.length, lengthArray.length);

    return padded;
  }

  private int rotr(int x, int n) {
    return (((x >>> n)) | (x << (32 - n)));
  }

  private int upperSigmaZero(int x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
  }

  private int upperSigmaOne(int x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
  }

  private int lowerSigmaZero(int x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3);
  }

  private int lowerSigmaOne(int x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10);
  }

  private int ch(int x, int y, int z) {
    return (x & y) ^ ((~ x) & z);
  }

  private int maj(int x, int y, int z) {
    return (x & y) ^ (x & z) ^ (y & z);
  }

  public String getHash(byte[] message) {
    outputByteArray("padded: ", message);

    for (int i = 0; i < message.length; i = i + 64) {
      int[] w = new int[64];

      for (int j = 0; j < 16; j++) {
        w[j] = ((message[i + (j * 4) + 0] & 0xFF) << 24) + ((message[i + (j * 4) + 1] & 0xFF) << 16) + ((message[i + (j * 4) + 2] & 0xFF) << 8) + ((message[i + (j * 4) + 3] & 0xFF));
      }

      for (int j = 16; j < 64; j++) {
        w[j] = lowerSigmaOne(w[j - 2]) + w[j - 7] + lowerSigmaZero(w[j - 15]) + w[j - 16];
      }

      int a = H[0];
      int b = H[1];
      int c = H[2];
      int d = H[3];
      int e = H[4];
      int f = H[5];
      int g = H[6];
      int h = H[7];

      for (int j = 0; j < 64; j++) {
        int T1 = h + upperSigmaOne(e) + ch(e, f, g) + K[j] + w[j];
        int T2 = upperSigmaZero(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
      }

      H[0] = a + H[0];
      H[1] = b + H[1];
      H[2] = c + H[2];
      H[3] = d + H[3];
      H[4] = e + H[4];
      H[5] = f + H[5];
      H[6] = g + H[6];
      H[7] = h + H[7];
    }

    return "" + hexString(H[0]) + hexString(H[1]) + hexString(H[2]) + hexString(H[3]) + hexString(H[4]) + hexString(H[5]) + hexString(H[6]) + hexString(H[7]);
  }
}
