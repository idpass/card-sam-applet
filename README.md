# SAM Applet

### General SW List

SW | DESCRIPTION
-- | -- 
0x9000 | No error
0x6982 | SCP Security Level is too low
0x6B00 | Incorrect parameters (P1,P2)
0x6700 | Wrong DATA length

### sam package
**sam** package contains the applet for encryption and decryption personas data. 

Applet allow encrypt and decrypt ONLY if persona is authenticated in auth applet until card reset (ATR) event

Each persona has their own slot with unique enc and mac keys

Random first data block, ALG_AES_CBC_ISO9797_M2 encryption algorithm and ALG_DES_MAC8_ISO9797_M2 signature algorithm are used in current implementation.

AID | DESCRIPTION
-- | --
F769647061737302 | Package AID
F769647061737302010001 | Applet AID. Last 4 digits of the AID (*0001*) is the applet version   

#### Install Parameters
ORDER | LENGTH | DESCRIPTION
-- | -- | --
0 | 1 | Secret. <br>Parameter for Shareble Interface Objects authentication. <br><br>*0x9E* - default value

If install parameters are not set, default values will be used (*0x9E*)

#### APDU Commands

##### SELECT

Secure Channel Protocol minimum level: *no auth*

C-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
CLA | 1 | 0x00
INS | 1 | 0xA4
P1 | 1 | 0x04
P2 | 1 | 0x00
LC | 1 | Applet instance AID length
DATA | var | Applet instance AID

R-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
DATA | 2 | Opened crypto slot id (equals to Index of authenticated persona)<br>If no opened slots (no authenticated Persona) - *0xFFFF* returns
SW | 2 | Status Word (see **General SW List** section)

##### ENCRYPT
Encrypt data in authenticated persona slot

Secure Channel Protocol minimum level: *no auth*

C-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
CLA | 1 | 0x00
INS | 1 | 0xEC
P1 | 1 | 0x00
P2 | 1 | 0x00
LC | 1 or 3 | length of data to encrypt<br>Maximum 1960 bytes for NXP EMV P60 chip
DATA | var | data to encrypt

R-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
DATA | var | Encrypted and signed data
SW | 2 | Status Word <br>0x6A85 - no open slots found (no authenticated persona)<br>See **General SW List** section for other SW

##### DECRYPT
Decrypt encrypted data in authenticated persona slot

Secure Channel Protocol minimum level: *no auth*

C-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
CLA | 1 | 0x00
INS | 1 | 0xDC
P1 | 1 | 0x00
P2 | 1 | 0x00
LC | 1 or 3 | length of data to decrypt<br>Maximum 1960 bytes for NXP EMV P60 chip
DATA | var | data to decrypt

R-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
DATA | var | Decrypted data
SW | 2 | Status Word <br>0x6984 - Signature verification failed<br>0x6A85 - no open slots found (no authenticated persona)<br>See **General SW List** section for other SW

### Contributors

Contributions are welcome!

- Newlogic Impact Lab
- Maksim Samarskiy
