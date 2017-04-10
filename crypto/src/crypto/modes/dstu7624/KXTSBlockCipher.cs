using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Modes
{
     public class KXtsSBlockCipher : BufferedBlockCipher
     {
          private byte[] IV;
          private byte[] s;

          private byte[] alpha1;

          private byte[] buffer;
          private byte[] temp;



          private int counter;
          

          public KXtsSBlockCipher(IBlockCipher cipher)
          {
               this.buf = new byte[cipher.GetBlockSize()];
               this.bufOff = 0;

               this.cipher = cipher;

               this.IV = new byte[cipher.GetBlockSize()];
               this.s = new byte[cipher.GetBlockSize()];
               this.alpha1 = new byte[cipher.GetBlockSize()];
               this.alpha1[0] = 0x02;

               this.buffer = new byte[cipher.GetBlockSize()];
               this.temp = new byte[cipher.GetBlockSize()];

               this.counter = 0;
               
          }
           
          
         
          public override string AlgorithmName
          {
               get { return cipher.AlgorithmName + "/XTS"; }
          }



          public override void Init(bool forEncryption, ICipherParameters parameters)
          {              
               if (parameters is ParametersWithIV)
               {
                    ParametersWithIV ivParam = (ParametersWithIV)parameters;
                    byte[] iv = ivParam.GetIV();

                    if (iv.Length < IV.Length)
                    {
                         Array.Copy(iv, 0, IV, IV.Length - iv.Length, iv.Length);
                         for (int i = 0; i < IV.Length - iv.Length; i++)
                         {
                              IV[i] = 0;
                         }
                    }
                    else
                    {
                         Array.Copy(iv, 0, IV, 0, IV.Length);
                    }

                    parameters = ivParam.Parameters;
               }
               else
               {
                    throw new ArgumentException("Invalid parameters passed to XTS mode");
               }

               
               cipher.Init(true, parameters);

               cipher.ProcessBlock(IV, 0, s, 0);

               cipher.Init(forEncryption, parameters);
                                            
          }

          public override int ProcessBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
          {
               if (input.Length - inOff < len)
               {
                    throw new DataLengthException("input buffer is too short");
               }

               if (output.Length - inOff < len)
               {
                    throw new DataLengthException("output buffer is too short");
               }

               int totalLength = len;
                              
               while (totalLength >= cipher.GetBlockSize())
               {    
                    ProcessBlock(input, inOff, output, outOff);
                    
                    totalLength -= cipher.GetBlockSize();
                    inOff += cipher.GetBlockSize();
                    outOff += cipher.GetBlockSize();
               }
               
               return len - totalLength;
          }
          
          
          private void ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
          {
               counter++;

               PowerOverField(cipher.GetBlockSize() * 8, alpha1, counter, temp);
               
               MultiplyOverField(cipher.GetBlockSize() * 8, temp, s, buffer);
                              
               Array.Reverse(buffer);

               Array.Copy(buffer, 0, temp, 0, cipher.GetBlockSize());
               
               for (int i = 0; i < cipher.GetBlockSize(); i++)
               {
                    buffer[i] ^= input[inOff + i];
               }

               cipher.ProcessBlock(buffer, 0, buffer, 0);

               for (int i = 0; i < cipher.GetBlockSize(); i++)
               {
                    output[outOff + i] = (byte)(buffer[i] ^ temp[i]);
               }       
          }




          public override int DoFinal(byte[] output, int outOff)
          {
               Reset();

               return 0;
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

          public override void Reset()
          {
               base.Reset();

               Array.Clear(buffer, 0, cipher.GetBlockSize());
               Array.Clear(temp, 0, cipher.GetBlockSize());
               Array.Clear(alpha1, 0, cipher.GetBlockSize());
               alpha1[0] = 0x02;

               counter = 0;
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
