# `sm` - Send Message

An extremely simple and minimalistic utility to securely send a message to someone with RSA.

# Getting Started

Let's say you want to securely send "password" from `Alice` to `Bob`.

First, Bob prepares for decryption:

```
> sm decrypt
generating RSA private key...
computing public key...
RSA public key:
00010000000000009F8E323CA22E37219C0C238DD7C2C1631565BFF582F12E7A93511B073B7A23F56180FA7F0F0D7749D0E2509D9FEA22DCA61A1BE6CF8B2BAC1F71609CD5456C93AE55E672DD2903770BE120ED3C98AA3BD69174E20C74FEFBDB3632BF968E5E0DD2A75CBE39FD34C7554A8F2D2186D65A4E466FAE45D212EDA1A341952144768E0FAAF8968F64FF7460FF7A676B280D924179EFF823680C701D30ED8EA61AACCE3D22B5EA7444D0656273991B3BB3DFC167EA4B89F2BB503566C81BC541831BE9356F942BDB2729378322BB32EF80AA52ECA4456AD2B7F5A1DD3DF55D917800823296B1A6BF122A5C102337A5AE5E08E64F8ABA9EDFEAD654413296CC21D295BB010001
decryption prepared! send your friend the RSA public key!
then, paste in their encrypted messages here to decrypt them!
```

Then, Bob sends the public key string to Alice for decryption.

On Alice's end, Alice writes

```
> sm encrypt 00010000000000009F8E323CA22E37219C0C238DD7C2C1631565BFF582F12E7A93511B073B7A23F56180FA7F0F0D7749D0E2509D9FEA22DCA61A1BE6CF8B2BAC1F71609CD5456C93AE55E672DD2903770BE120ED3C98AA3BD69174E20C74FEFBDB3632BF968E5E0DD2A75CBE39FD34C7554A8F2D2186D65A4E466FAE45D212EDA1A341952144768E0FAAF8968F64FF7460FF7A676B280D924179EFF823680C701D30ED8EA61AACCE3D22B5EA7444D0656273991B3BB3DFC167EA4B89F2BB503566C81BC541831BE9356F942BDB2729378322BB32EF80AA52ECA4456AD2B7F5A1DD3DF55D917800823296B1A6BF122A5C102337A5AE5E08E64F8ABA9EDFEAD654413296CC21D295BB010001
public key decoded! type a line to encrypt it
```

From here, Alice can type in whatever she likes and it will get encrypted

```
> sm encrypt
password
68FA284E39E7D99DE85B6902483CF0460BAA1C9DBC2C4D7AD69A85C7B59B2131D0F8C9F59975E7176FA6ABF9D9BAD7AB7C818DDAC1B2047EED9FA89EC6D45363A4D8D867BE78332AD9C3105599C9C4FE163DAEDC9209472546A7C40F7975EF11BDD69272980F2BFED3814BB407B19749B4A4A36C399A01AD174838C59B773313A8906792240EB8F3DB9BB4C34C1E5660EE0537D3ADADF80F7AB51A0E2A14C0CA461FA10E26C439CE48E02C34C200B5BCC91526EA06BD9442584AE8FA71AFBB212661551793E324C263C942540F47A55A58206CDFB31961301EA3D57BB5C0EE9A7AEC1F134E711DD7EF872F232975D1AD1A90CCD9D33F224386EF3903F5F2CA5E
```

Then, Bob can receive receive what Alice sends and decrypt it

```
...
decryption prepared! send your friend the RSA public key!
then, paste in their encrypted messages here to decrypt them!
68FA284E39E7D99DE85B6902483CF0460BAA1C9DBC2C4D7AD69A85C7B59B2131D0F8C9F59975E7176FA6ABF9D9BAD7AB7C818DDAC1B2047EED9FA89EC6D45363A4D8D867BE78332AD9C3105599C9C4FE163DAEDC9209472546A7C40F7975EF11BDD69272980F2BFED3814BB407B19749B4A4A36C399A01AD174838C59B773313A8906792240EB8F3DB9BB4C34C1E5660EE0537D3ADADF80F7AB51A0E2A14C0CA461FA10E26C439CE48E02C34C200B5BCC91526EA06BD9442584AE8FA71AFBB212661551793E324C263C942540F47A55A58206CDFB31961301EA3D57BB5C0EE9A7AEC1F134E711DD7EF872F232975D1AD1A90CCD9D33F224386EF3903F5F2CA5E
password
```
