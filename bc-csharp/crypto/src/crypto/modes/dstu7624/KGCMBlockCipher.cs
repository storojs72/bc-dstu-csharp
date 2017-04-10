using System;

using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes.Gcm;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Modes
{
     /// <summary>
     /// Implements the GCM mode for DSTU 7624 block cipher
     /// </summary>
     class KGcmBlockCipher : IAeadBlockCipher
     {
          private readonly IBlockCipher cipher;
          private readonly BufferedBlockCipher ctrCipher;

          
          private int macSize;

          private bool forEncryption;

          //initial buffers
          private byte[] macBlock = new byte[0];
          private byte[] initialAssociatedText;
          private byte[] IV;

        
          //buffers for mac
          private byte[] H;
          private byte[] b;
          private byte[] temp;

          private int lambda_o;
          private int lambda_c;



          public KGcmBlockCipher(IBlockCipher cipher)
          {
               this.cipher = cipher;
               this.ctrCipher = new BufferedBlockCipher(new KCtrBlockCipher(this.cipher));
               this.macSize = 0;

               this.IV = new byte[cipher.GetBlockSize()];
               this.H = new byte[cipher.GetBlockSize()];
               this.b = new byte[cipher.GetBlockSize()];
               this.temp = new byte[cipher.GetBlockSize()];

               
               this.lambda_c = 0;
               this.lambda_o = 0;
          }
                    
          public string AlgorithmName
          {
               get { return cipher.AlgorithmName + "/GCM"; }
          }

          public IBlockCipher GetUnderlyingCipher()
          {
               return cipher;
          }

          public void Init(bool forEncryption, ICipherParameters parameters)
          {
               this.forEncryption = forEncryption;

               KeyParameter engineParam;
               if (parameters is AeadParameters)
               {
                    AeadParameters param = (AeadParameters)parameters;

                    byte[] iv = param.GetNonce();
                    int diff = IV.Length - iv.Length;
                    Array.Copy(iv, 0, IV, diff, iv.Length);
                    Array.Clear(IV, 0, diff);

                    initialAssociatedText = param.GetAssociatedText();

                    int macSizeBits = param.MacSize;
                  
                    if (macSizeBits < 64 || macSizeBits > cipher.GetBlockSize() * 8 || macSizeBits % 8 != 0)
                    {
                         throw new ArgumentException("Invalid value for MAC size: " + macSizeBits);
                    }

                    macSize = macSizeBits / 8;
                    engineParam = param.Key;

                    
                    if (initialAssociatedText != null)
                    {
                         ProcessAadBytes(initialAssociatedText, 0, initialAssociatedText.Length);
                    }

               }
               else if (parameters is ParametersWithIV)
               {
                    ParametersWithIV param = (ParametersWithIV)parameters;

                    byte[] iv = param.GetIV();
                    int diff = IV.Length - iv.Length;
                    Array.Copy(iv, 0, IV, diff, iv.Length);
                    Array.Clear(IV, 0, diff);


                    initialAssociatedText = null;

                    macSize = cipher.GetBlockSize();

                    engineParam = param.Parameters as KeyParameter;
               }
               else
               {
                    throw new ArgumentException("invalid parameters passed to GCM");
               }

               this.macBlock = new byte[cipher.GetBlockSize()];

                           
               ctrCipher.Init(true, new ParametersWithIV(engineParam, IV));
               
               cipher.Init(true, engineParam);
          }



          public int GetBlockSize()
          {
               return cipher.GetBlockSize();
          }

          public void ProcessAadByte(byte input)
          {
               throw new NotImplementedException();
          }


          public void ProcessAadBytes(byte[] input, int inOff, int len)
          {
               lambda_o = len * 8;

               cipher.ProcessBlock(H, 0, H, 0);
               
               int totalLength = len;
               int inOff_ = inOff;

               while (totalLength > 0)
               {

                    for (int i = 0; i < cipher.GetBlockSize(); i++)
                    {
                         b[i] ^= input[inOff_ + i];
                    }
                    MultiplyOverField(cipher.GetBlockSize() * 8, b, H, temp);

                    Array.Reverse(temp);

                    Array.Copy(temp, 0, b, 0, cipher.GetBlockSize());

                    totalLength -= cipher.GetBlockSize();
                    inOff_ += cipher.GetBlockSize();
               }             

          }

          public void ProcessAadBytes(byte[] input, int inOff, int len, byte[] mac, int macOff)
          {
               lambda_o = len * 8;
            
               cipher.ProcessBlock(H, 0, H, 0);
               
               int totalLength = len;
               int inOff_ = inOff;

               while (totalLength > 0)
               {

                    for (int i = 0; i < cipher.GetBlockSize(); i++)
                    {
                         b[i] ^= input[inOff_ + i];
                    }
                    MultiplyOverField(cipher.GetBlockSize() * 8, b, H, temp);

                    Array.Reverse(temp);

                    Array.Copy(temp, 0, b, 0, cipher.GetBlockSize());

                    totalLength -= cipher.GetBlockSize();
                    inOff_ += cipher.GetBlockSize();
               }


               Array.Clear(temp, 0, cipher.GetBlockSize());
               intTobytes(lambda_o, temp, 0);

               for (int i = 0; i < cipher.GetBlockSize(); i++)
               {
                    b[i] ^= temp[i];
               }

               cipher.ProcessBlock(b, 0, macBlock, 0);

               Array.Copy(macBlock, 0, mac, 0, macSize);

          }

          public int ProcessByte(byte input, byte[] outBytes, int outOff)
          {
               throw new NotImplementedException();
          }
                    

          public int ProcessBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
          {
               if (output.Length - outOff < len + macSize)
               {
                    throw new ArgumentException("output buffer is too short");
               }

               lambda_c = len * 8;

               //use alternative CTR cipher to produce output
               int outOff_;
               int resultLen;
               if (forEncryption)
               {
                   

                    outOff_ = outOff;
                    resultLen = ctrCipher.ProcessBytes(input, inOff, len, output, outOff);

                    ctrCipher.DoFinal(output, resultLen);
                                        
                    CalculateMac(output, outOff_, len);
               }
               else
               {
                    int inOff_ = inOff;

                    CalculateMac(input, inOff_, len);
                                       
                    resultLen = ctrCipher.ProcessBytes(input, inOff, len, output, outOff);
                    ctrCipher.DoFinal(output, resultLen);
               }



               return resultLen;
          }

          private void CalculateMac(byte[] input, int inOff, int len)
          {
               int totalLength = len;
               int inOff_ = inOff;

               while (totalLength > 0)
               {
                    for (int i = 0; i < cipher.GetBlockSize(); i++)
                    {
                         b[i] ^= input[inOff_ + i];
                    }

                    MultiplyOverField(cipher.GetBlockSize() * 8, b, H, temp);

                    Array.Reverse(temp);

                    Array.Copy(temp, 0, b, 0, cipher.GetBlockSize());

                    totalLength -= cipher.GetBlockSize();
                    inOff_ += cipher.GetBlockSize();

               }

               Array.Clear(temp, 0, cipher.GetBlockSize());
               intTobytes(lambda_o, temp, 0);
               intTobytes(lambda_c, temp, cipher.GetBlockSize() / 2);

               for (int i = 0; i < cipher.GetBlockSize(); i++)
               {
                    b[i] ^= temp[i];
               }

               cipher.ProcessBlock(b, 0, macBlock, 0);
               
          }


          public int DoFinal(byte[] outBytes, int outOff)
          {
               if (forEncryption)
               {
                    Array.Copy(macBlock, 0, outBytes, outOff, macSize);

                    Reset();

                    return macSize;
               }
               else
               {
                    byte[] mac = new byte[macSize];
                    Array.Copy(outBytes, outOff, mac, 0, macSize);

                    byte[] calculatedMac = new byte[macSize];
                    Array.Copy(macBlock, 0, calculatedMac, 0, macSize);

                    if (!Arrays.AreEqual(mac, calculatedMac))
                    {
                         throw new InvalidOperationException("Mac verification failed");
                    }

                    Reset();

                    return 0;
               }
          }


          public byte[] GetMac()
          {
               byte[] mac = new byte[macSize];

               Array.Copy(macBlock, 0, mac, 0, macSize);

               return mac;
          }

          public int GetUpdateOutputSize(int len)
          {
               return len;
          }

          public int GetOutputSize(int len)
          {
               if (forEncryption)
               {
                    return len;
               }
               else
               {
                    return len + macSize;
               }
               
          }

          public void Reset()
          {
               this.H = new byte[cipher.GetBlockSize()];
               this.b = new byte[cipher.GetBlockSize()];
               this.temp = new byte[cipher.GetBlockSize()];


               this.lambda_c = 0;
               this.lambda_o = 0;

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



          private void PowerOverField(int blockSizeBits, byte[] x, int power, byte[] powered_x)
          {
               //Powering over GF(2^m), GF(2^256), GF(2^512) with correspondent extension polynomials: 
               ///
               /// GF(2^128) | x^128 + x^7 + x^2 + x
               /// GF(2^256) | x^256 + x^10 + x^5 + x^2 + 1
               /// GF(2^512) | x^512 + x^8 + x^5 + x^2 + 1
               ///
               //Thanks to João H de A Franco script. https://jhafranco.com/2012/02/17/multiplication-over-the-binary-finite-field-gf2m/


               byte[] copy1 = new byte[x.Length];
               byte[] copy2 = new byte[x.Length];
               Array.Copy(x, 0, copy1, 0, blockSizeBits / 8);
               Array.Copy(x, 0, copy2, 0, blockSizeBits / 8);

               if (power == 1)
               {
                    Array.Copy(copy1, 0, powered_x, 0, blockSizeBits / 8);
                    return;
               }


               for (int i = 0; i < power - 1; i++)
               {
                    MultiplyOverField(blockSizeBits, copy1, copy2, powered_x);
                    Array.Copy(powered_x, 0, copy1, 0, x.Length);
               }

          }

          private void MultiplyOverField(int blockSizeBits, byte[] x, byte[] y, byte[] x_mult_y)
          {
               //Multiplication over GF(2^m), GF(2^256), GF(2^512) with correspondent extension polynomials: 
               ///
               /// GF(2^128) | x^128 + x^7 + x^2 + x
               /// GF(2^256) | x^256 + x^10 + x^5 + x^2 + 1
               /// GF(2^512) | x^512 + x^8 + x^5 + x^2 + 1
               ///
               //Thanks to João H de A Franco script. https://jhafranco.com/2012/02/17/multiplication-over-the-binary-finite-field-gf2m/
               
               byte[] copy1 = new byte[cipher.GetBlockSize()];
               byte[] copy2 = new byte[cipher.GetBlockSize()];

               Array.Copy(x, 0, copy1, 0, cipher.GetBlockSize());
               Array.Copy(y, 0, copy2, 0, cipher.GetBlockSize());


               Array.Reverse(copy1);
               Array.Reverse(copy2);


               BigInteger mask1;
               BigInteger mask2;
               BigInteger polyred;

               switch (blockSizeBits)
               {
                    case 128:
                         mask1 = mask1_128;
                         mask2 = mask2_128;
                         polyred = polyred_128;
                         break;
                    case 256:
                         mask1 = mask1_256;
                         mask2 = mask2_256;
                         polyred = polyred_256;
                         break;
                    case 512:
                         mask1 = mask1_512;
                         mask2 = mask2_512;
                         polyred = polyred_512;
                         break;
                    default:
                         mask1 = mask1_128;
                         mask2 = mask2_128;
                         polyred = polyred_128;
                         break;
               }

               BigInteger p = BigInteger.Zero;
               BigInteger p1 = new BigInteger(1, copy1);
               BigInteger p2 = new BigInteger(1, copy2);
                              
               while (!p2.Equals(BigInteger.Zero))
               {
                    if (p2.And(BigInteger.One).Equals(BigInteger.One))
                    {
                         p = p.Xor(p1);
                    }

                    p1 = p1.ShiftLeft(1);

                    if (!p1.And(mask1).Equals(BigInteger.Zero))
                    {
                         p1 = p1.Xor(polyred);
                    }

                    p2 = p2.ShiftRight(1);
               }

               byte[] got = p.And(mask2).ToByteArrayUnsigned();

               Array.Clear(x_mult_y, 0, cipher.GetBlockSize());

               Array.Copy(got, 0, x_mult_y, 0, got.Length);
               
          }


          #region MULTIPLICATION CONSTANTS

          private static readonly BigInteger mask1_128 = new BigInteger("340282366920938463463374607431768211456", 10);
          private static readonly BigInteger mask2_128 = new BigInteger("340282366920938463463374607431768211455", 10);
          private static readonly BigInteger polyred_128 = new BigInteger("135", 10);

          private static readonly BigInteger mask1_256 = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639936", 10);
          private static readonly BigInteger mask2_256 = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10);
          private static readonly BigInteger polyred_256 = new BigInteger("1061", 10);

          private static readonly BigInteger mask1_512 = new BigInteger("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084096", 10);
          private static readonly BigInteger mask2_512 = new BigInteger("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084095", 10);
          private static readonly BigInteger polyred_512 = new BigInteger("293", 10);

          #endregion

          
     }
}
