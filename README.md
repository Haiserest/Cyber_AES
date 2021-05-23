# Cyber_AES
            Encryption            &amp;                 Decryption

       TEXT + AES Key                         Digital Signature + Public Key        AES Encrypt File--------------+
            |                                               |                               |                     |
            |                                               |                               |                     |
            V                                               V                               V                     |
      AES Encrypt File                                     HASH                          SHA 512                  |
            |                                               |                               |                     |
            |                                               |                               |                     |
            V                                               |                               V                     |
         SHA 512                                            |                              HASH                   |
            |                                               |                               |                     |
            |                                               +------------- Verify ----------+                     |
            V                                                                |                                    |
           HASH                                                              |                                    |
            |                                                                V                                    |
            |                                                                +------------------------------------+
            V                                                                V
       Private Key                                                        AES Key         
            |                                                                |
            |                                                                |
            V                                                                V
     Digital Signature                                                    Plaintext
