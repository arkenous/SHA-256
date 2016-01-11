package net.trileg.sha256;

public class Main {

  public static void main(String[] args) {
    SHA256 sha256 = new SHA256();
    byte[] message = {(byte)0x61, (byte)0x62, (byte)0x63};
    String result = sha256.getHash(sha256.padding(message));
    System.out.println(result);
  }
}
