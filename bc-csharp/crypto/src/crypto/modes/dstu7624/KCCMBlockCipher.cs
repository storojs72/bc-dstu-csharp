using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Modes
{
     public class KCcmBlockCipher : IAeadBlockCipher
     {
          private IBlockCipher cipher;
          private ICipherParameters keyParam;

          private const int BYTES_IN_INT = 4;

          private bool forEncryption;

          private byte[] nonce;
          private byte[] initialAssociatedText;
          private byte[] macBlock;
          private byte[] mac;

          private byte[] G1;
          private byte[] buffer;
          private byte[] b;
          private int macSize;


          private byte[] s;
          private byte[] counter;


          
          private int Nb_ = 4;
          public int Nb
          {
               get { return Nb_; }
               set 
               {
                    if (value == 4 || value == 6 ||value == 8 )
                    {
                         Nb_ = value;
                    }
                    else
                    {
                         throw new ArgumentException("Nb = 4 is recommended by DSTU7624 but can be changed to only 6 and 8");
                    }
               }
          }


          /**
          * Basic constructor.
          *
          * @param cipher the block cipher to be used.
          */
          public KCcmBlockCipher(
            IBlockCipher cipher)
          {
               this.cipher = cipher;
               this.macBlock = new byte[cipher.GetBlockSize()];

               this.G1 = new byte[cipher.GetBlockSize()];
               this.buffer = new byte[cipher.GetBlockSize()];
               this.b = new byte[cipher.GetBlockSize()];

               this.s = new byte[cipher.GetBlockSize()];
               this.counter = new byte[cipher.GetBlockSize()];
               counter[0] = 0x01;
          }



          public void Init(bool forEncryption, ICipherParameters parameters)
          {
               Reset();

               this.forEncryption = forEncryption;

               ICipherParameters cipherParameters;
               if (parameters is AeadParameters)
               {
                    AeadParameters param = (AeadParameters)parameters;

                    nonce = param.GetNonce();
                    initialAssociatedText = param.GetAssociatedText();

                    if (param.MacSize > 512 || param.MacSize < 64)
                    {
                         throw new ArgumentException("invalid mac size parameter passed to KCCM");
                    }

                    macSize = param.MacSize / 8;
                    cipherParameters = param.Key;
               }
               else if (parameters is ParametersWithIV)
               {
                    ParametersWithIV param = (ParametersWithIV)parameters;

                    nonce = param.GetIV();
                    initialAssociatedText = null;
                    macSize = cipher.GetBlockSize();
                    cipherParameters = param.Parameters;
               }
               else
               {
                    throw new ArgumentException("invalid parameters passed to KCCM");
               }

               // NOTE: Very basic support for key re-use, but no performance gain from it
               if (cipherParameters != null)
               {
                    keyParam = cipherParameters;
               }

               this.mac = new byte[macSize];

               cipher.Init(true, keyParam);
          }



          public void ProcessAadBytes(byte[] authText, int inOff, int len)
          {
               throw new NotImplementedException("To ProcessAadBytes in KCCM mode input length should be known. Use overloaded method with same name");
          }



          public void ProcessAadBytes(byte[] authText, int authOff, int authLen, int inLen)
          {
               Check.DataLength(authText, authOff, authLen, "authText buffer is too short");

               if (authLen < cipher.GetBlockSize() || authLen % cipher.GetBlockSize() != 0)
               {
                    throw new ArgumentException("Padding not supported");
               }

               Array.Copy(nonce, 0, G1, 0, nonce.Length - Nb_ - 1);

               intTobytes(inLen, buffer, 0); // for G1
                                             
               Array.Copy(buffer, 0, G1, nonce.Length - Nb_ - 1, BYTES_IN_INT);

               G1[G1.Length - 1] = GetFlagByte(true, macSize);
                                         
               cipher.ProcessBlock(G1, 0, macBlock, 0);
                              
               intTobytes(authLen, buffer, 0); // for G2
               
               if (authLen <= cipher.GetBlockSize() - Nb_)
               {
                    for (int i = 0; i < authLen; i++)
                    {
                         buffer[i + Nb_] ^= authText[authOff + i];
                    }

                    for (int i = 0; i < cipher.GetBlockSize(); i++)
                    {
                         macBlock[i] ^= buffer[i];
                    }
                                      
                    cipher.ProcessBlock(macBlock, 0, macBlock, 0);

                    return;
               }

               for (int i = 0; i < cipher.GetBlockSize(); i++)
               {
                    macBlock[i] ^= buffer[i];
               }

               cipher.ProcessBlock(macBlock, 0, macBlock, 0);

               while (authLen != 0)
               {                    
                    for (int i = 0; i < cipher.GetBlockSize(); i++)
                    {
                         macBlock[i] ^= authText[i + authOff];
                    }
                    cipher.ProcessBlock(macBlock, 0, macBlock, 0);
                    
                    authOff += cipher.GetBlockSize();
                    authLen -= cipher.GetBlockSize();
                                       
               }
          }
          
          public int ProcessBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
          {
               Check.DataLength(input, inOff, len, "input buffer is too short");
               Check.OutputLength(output, outOff, len, "output buffer is too short");
           
               if (forEncryption)
               {
                    if ((len % cipher.GetBlockSize()) != 0)
                    {
                         throw new DataLengthException("Padding not supported");
                    }

                    CalculateMac(input, inOff, len);

                    cipher.ProcessBlock(nonce, 0, s, 0);

                    int totalLength = len;
                    while (totalLength > 0)
                    {
                         ProcessBlock(input, inOff, len, output, outOff);

                         totalLength -= cipher.GetBlockSize();

                         inOff += cipher.GetBlockSize();
                         outOff += cipher.GetBlockSize();
                    }

                    for (int i = 0; i < counter.Length; i++)
                    {
                         s[i] += counter[i];
                    }

                    cipher.ProcessBlock(s, 0, buffer, 0);
               }
               else
               {
                    if ((len - macSize) % cipher.GetBlockSize() != 0)
                    {
                         throw new DataLengthException("Padding not supported");
                    }
                                                            
                    cipher.ProcessBlock(nonce, 0, s, 0);
                                       
                    int blocks = len / cipher.GetBlockSize();
                    
                    for (int i = 0; i < blocks; i++)
                    {
                         ProcessBlock(input, inOff, len, output, outOff);

                         inOff += cipher.GetBlockSize();
                         outOff += cipher.GetBlockSize();
                    }

                    if (len > inOff)
                    {
                         //Process last block if needed
                         for (int i = 0; i < counter.Length; i++)
                         {
                              s[i] += counter[i];
                         }

                         cipher.ProcessBlock(s, 0, buffer, 0);
                    
                         for (int i = 0; i < macSize; i++)
                         {
                              output[outOff + i] = (byte)(buffer[i] ^ input[inOff + i]);   
                         }
                         inOff += macSize;
                         outOff += macSize;
                    }
                                       
                                       
                    for (int i = 0; i < counter.Length; i++)
                    {
                         s[i] += counter[i];
                    }

                    cipher.ProcessBlock(s, 0, buffer, 0);
                    
                    Array.Copy(output, outOff - macSize, buffer, 0, macSize);                    
               }

               return len;
          }

          private void ProcessBlock(byte[] input, int inOff, int len, byte[] output, int outOff)
          {

               for (int i = 0; i < counter.Length; i++)
               {
                    s[i] += counter[i];
               }

               cipher.ProcessBlock(s, 0, buffer, 0);
                              
               for (int i = 0; i < cipher.GetBlockSize(); i++)
               {
                    output[outOff + i] = (byte)(buffer[i] ^ input[inOff + i]);
               }
          }

          private void CalculateMac(byte[] input, int inOff, int len)
          {              
               int totalLength = len;

               while (totalLength > 0)
               {
                    for (int i = 0; i < cipher.GetBlockSize(); i++)
                    {
                         macBlock[i] ^= input[inOff + i];
                    }
                                         
                    cipher.ProcessBlock(macBlock, 0, macBlock, 0);

                    totalLength -= cipher.GetBlockSize();
                    inOff += cipher.GetBlockSize();
               }                               
          }



          public int ProcessByte(byte input, byte[] outBytes, int outOff)
          {
               throw new NotImplementedException();
          }
          

          public int DoFinal(byte[] outBytes, int outOff)
          {
               if (forEncryption)
               {
                    for (int i = 0; i < macSize; i++)
                    {
                         outBytes[outOff + i] = (byte)(buffer[i] ^ macBlock[i]);
                    }
                    
                    Reset();

                    return macSize;
               }
               else
               {                   
                    CalculateMac(outBytes, 0, outOff - macSize);
                    
                    Array.Copy(macBlock, 0, mac, 0, macSize);

                    byte[] calculatedMac = new byte[macSize];

                    Array.Copy(buffer, 0, calculatedMac, 0, macSize);
                    
                    if (!Arrays.AreEqual(mac, calculatedMac))
                    {
                         throw new InvalidCipherTextException("mac check in CCM failed");
                    }

                    Reset();

                    return 0;
               }
               
              
          }

          public byte[] GetMac()
          {
               Array.Copy(macBlock, 0, mac, 0, macSize);
               return mac;
          }

          public string AlgorithmName
          {
               get { return cipher.AlgorithmName + "/CCM"; }
          }

          public IBlockCipher GetUnderlyingCipher()
          {
               return cipher;
          }
          public int GetBlockSize()
          {
               return cipher.GetBlockSize();
          }

          public int GetUpdateOutputSize(int len)
          {
               return len;
          }

          public int GetOutputSize(int len)
          {
               return len + macSize;
          }

          public void Reset()
          {              
               Array.Clear(G1, 0, cipher.GetBlockSize());
               Array.Clear(buffer, 0, cipher.GetBlockSize());
               Array.Clear(b, 0, cipher.GetBlockSize());
               Array.Clear(counter, 0, cipher.GetBlockSize());
               counter[0] = 0x01;
          }




          public void ProcessAadByte(byte input)
          {
               throw new NotImplementedException();
          }

          //int to array of bytes
          private static void intTobytes(
                    int num,
                    byte[] outBytes,
                    int outOff)
          {
               outBytes[outOff + 3] = (byte)(num >> 24);
               outBytes[outOff + 2] = (byte)(num >> 16);
               outBytes[outOff + 1] = (byte)(num >> 8);
               outBytes[outOff] = (byte)num;
          }

          private byte GetFlagByte(bool authTextPresents, int macSize)
          {
               StringBuilder flagByte = new StringBuilder();

               if (authTextPresents)
               {
                    flagByte.Append("1");
               }
               else
               {
                    flagByte.Append("0");
               }
               
               
               switch (macSize)
               {
                    case 8:
                         flagByte.Append("010"); // binary 2
                         break;
                    case 16:
                         flagByte.Append("011"); // binary 3
                         break;
                    case 32:
                         flagByte.Append("100"); // binary 4
                         break;
                    case 48:
                         flagByte.Append("101"); // binary 5
                         break;
                    case 64:
                         flagByte.Append("110"); // binary 6
                         break;
               }

               //Convert Nb to binary
               string binaryNb = Convert.ToString(Nb_ - 1, 2);
               while (binaryNb.Length < 4)
               {
                    binaryNb = binaryNb.Insert(0, "0");
               }

               flagByte.Append(binaryNb);

               //Console.WriteLine((Nb_ - 1).ToString() + " | " + flagByte.ToString());

               return Convert.ToByte(flagByte.ToString(), 2);



             

               //if (authTextPresents)
               //{
               //     switch (macSize)
               //     {
               //          case 8:
               //               return lookUp1[0];

               //          case 16:
               //               return lookUp1[1];

               //          case 32:
               //               return lookUp1[2];

               //          case 48:
               //               return lookUp1[3];

               //          case 64:
               //               return lookUp1[4];

               //          default:
               //               return lookUp1[0];
               //     }
               //}
               //else
               //{
               //     switch (macSize)
               //     {
               //          case 8:
               //               return lookUp2[0];

               //          case 16:
               //               return lookUp2[1];

               //          case 32:
               //               return lookUp2[2];

               //          case 48:
               //               return lookUp2[3];

               //          case 64:
               //               return lookUp2[4];

               //          default:
               //               return lookUp2[0];
               //     }
               //}
          }



     }
}
