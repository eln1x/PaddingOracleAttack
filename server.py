#!/usr/bin/env python
#Author: Ahmad Mahfouz @eln1x
#Description: bad implementation CBC for padding oracle attack
import socket
import threading
from Crypto.Cipher import AES
from binascii import hexlify,unhexlify


class ThreadedServer(object):
  def __init__(self, host, port):
    self.host = host
    self.port = port
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.sock.bind((self.host, self.port))
    self.secretKey = "6374663270776e21"
    self.iv = "7669683478307273"

  def listen(self):
    print "Starting Padding Oracle attack - Vulnerable Server"           
    self.sock.listen(5)
    while True:
      client, address = self.sock.accept()
      print "[+] Connection from %s"  %str(address)
      client.settimeout(60)
      threading.Thread(target = self.listenToClient,args = (client,address)).start()

  def listenToClient(self, client, address):
    size = 1024
    while True:
      try:
        data = client.recv(size)
        if data:

          if data.startswith("Decrypt:"):
            try:
              ciphertext = data.split("Decrypt:")[1].strip()
              decrypted = self.decrypt(unhexlify(ciphertext))
              if "INTERNAL SERVER ERROR" not in decrypted:
                response = "Plain-text message is: %s\nGoodjob!" %decrypted
              else:
                response = "Server ERROR, Goodbye"
            except Exception as e:
              print e
              response = "Not Acceptable!"

            client.send(response)
            client.close()
            break

          # elif data.startswith("Encrypt:"):
          #   plaintext = data.split("Encrypt:")[1]
          #   data = self.encrypt(plaintext)
          #   msg = "Encrypted message in HEX: \n%s" %data.encode('hex')
          #   response = msg
          #   client.send(response)
          #   client.close()

          else:
            response = """
Something went wrong!
Example Usage
Decrypt:748bffd64578632dd524d4c8d3788ef3
Plain-text message is: Hello Crypto!
Goodbye!
            """
            client.send(response)
            client.close()
          response = data
          client.send(response)
        else:
          raise error('Client disconnected')

        client.close()
      except:
        client.close()
    return False

  def decrypt(self,ciphertext):
    cipher = AES.new(self.secretKey, AES.MODE_CBC, self.iv)
    return self.ispkcs7(cipher.decrypt(ciphertext))

  def ispkcs7(self,plaintext):
    l = len(plaintext)
    c = ord(plaintext[l-1])                       
    if (c > 16) or (c < 1):
      return "INTERNAL SERVER ERROR"
    if plaintext[l-c:] != chr(c)*c:
      return "INTERNAL SERVER ERROR"
    return plaintext

  def encrypt(self,plaintext):
    cipher = AES.new(self.secretKey, AES.MODE_CBC, self.iv)
    ciphertext = cipher.encrypt(self.pkcs7(plaintext))
    return ciphertext

  def pkcs7(self,plaintext):
    padbytes = 16 - len(plaintext) % 16
    pad = padbytes * chr(padbytes)
    return plaintext + pad 


if __name__ == "__main__":

  port_num = 10000

  ThreadedServer('',port_num).listen()

