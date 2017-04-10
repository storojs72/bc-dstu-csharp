# bc-dstu
BouncyCastle with new ukrainian national standarts of block cipher (DSTU7624) and hash function (DSTU7564)
Initial implemetations of DSTU 7624 (block cipher) and DSTU 7564 (hash function)


Great thanks Roman Oleinikov for initial C implementations:
----------------------------------------------------------------------------------
https://github.com/Roman-Oliynykov/Kupyna-reference
https://github.com/Roman-Oliynykov/Kalyna-reference
----------------------------------------------------------------------------------



and João H de A Franco for Python implementation of Multiplication over binary finite field:
----------------------------------------------------------------------------------
https://jhafranco.com/2012/02/17/multiplication-over-the-binary-finite-field-gf2m/
----------------------------------------------------------------------------------



List of added files for DSTU 7624:



test/src/crypto/test/DSTU7624Tests.cs            --------> Tests for 10 modes of DSTU 7624

src/crypto/engines/DSTU7624Engine.cs             --------> Initial implementation of DSTU 7624

src/crypto/engines/DSTU7624WrapEngine.cs         --------> Key wrap mode

src/crypto/macs/DSTU7624Mac.cs                   --------> Mac mode

src/crypto/modes/dstu7624/KCFBBlockCipher.cs     --------> CFB mode 

src/crypto/modes/dstu7624/KCTRBlockCipher.cs     --------> CTR mode

src/crypto/modes/dstu7624/KCCMBlockCipher.cs     --------> CCM mode

src/crypto/modes/dstu7624/KGCMBlockCipher.cs     --------> GCM/GMAC mode

src/crypto/modes/dstu7624/KXTSBlockCipher.cs     --------> XTS mode

src/crypto/modes/KBufferedBlockCipher.cs         --------> Same as 'BufferedBlockCipher.cs' with slightly different last block (if partial) processing for DSTU 7624 CFB mode

test/src/crypto/test/KBufferedBlockCipherTest.cs --------> Same as 'BufferedBlockCipherTests.cs' but 'KBufferedBlockCipher.cs' is used instead of 'BufferedBlockCipher.cs'




List of added files for DSTU 7564:


test/src/crypto/test/DSTU7564Tests.cs            --------> Tests for 2 modes DSTU 7564

src/crypto/digests/DSTU7564Digest.cs             --------> Initial implementation of DSTU 7564

src/crypto/macs/DSTU7564Mac.cs                   --------> Mac engine on top of DSTU7564 hash function
