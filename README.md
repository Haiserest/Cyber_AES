# Cyber_AES

file:       

                        Encrypt_Decrypt.exe
                        Encrypt_Decrypt.py
![file](https://user-images.githubusercontent.com/69398619/119356885-216e5e00-bcd1-11eb-85dc-295970d27a70.PNG)


# Home:

![home](https://user-images.githubusercontent.com/69398619/119356521-bae94000-bcd0-11eb-9789-fb2fadb98e5c.PNG)

# Picture File:

![Picture_Encrypt](https://user-images.githubusercontent.com/69398619/119356535-c0468a80-bcd0-11eb-8ae5-18564a733a4d.PNG)

# Text File:

![Text_Encrypt](https://user-images.githubusercontent.com/69398619/119356540-c2a8e480-bcd0-11eb-9a1f-081f2b1a303b.PNG)



# Diagram

            Encryption         &                 Decryption

       TEXT + AES Key                     Digital Signature + Public Key        AES Encrypt File--------------+
            |                                           |                               |                     |
            |                                           |                               |                     |
            V                                           V                               V                     |
      AES Encrypt File                                 HASH                          SHA 512                  |
            |                                           |                               |                     |
            |                                           |                               |                     |
            V                                           |                               V                     |
         SHA 512                                        |                              HASH                   |
            |                                           |                               |                     |
            |                                           +------------- Verify ----------+                     |
            V                                                            |                                    |
           HASH                                                          |                                    |
            |                                                            V                                    |
            |                                                            +------------------------------------+
            V                                                            V
       Private Key                                                    AES Key         
            |                                                            |
            |                                                            |
            V                                                            V
     Digital Signature                                               Plaintext
