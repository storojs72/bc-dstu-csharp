using System;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;


namespace Org.BouncyCastle.Crypto.Macs
{
     /**
     * implementation of DSTU 7624 MAC mode
     */
     public class Dstu7624Mac : IMac
     {
          private int macSize;
                    
          private Dstu7624Engine engine;
          private int blockSize;

          private byte[] c, cTemp, kDelta;
                   
       
          public Dstu7624Mac(int blockSizeBits, int keySizeBits, int q)
          {
               this.engine = new Dstu7624Engine(blockSizeBits, keySizeBits);
               this.blockSize = blockSizeBits / 8;
               this.macSize = q / 8;
               this.c = new byte[blockSize];
               this.cTemp = new byte[blockSize];
               this.kDelta = new byte[blockSize];
               
          }
                    
          public void Init(ICipherParameters parameters)
          {
               Reset();

               if (parameters is KeyParameter)
               {
                    engine.Init(true, (KeyParameter)parameters);
                    engine.ProcessBlock(kDelta, 0, kDelta, 0);
                    
               }
               else
               {
                    throw new ArgumentException("invalid parameter passed to Dstu7624Mac init - "
                    + Platform.GetTypeName(parameters));
               }             
          }

          public string AlgorithmName
          {
               get { return "Dstu7624Mac"; }
          }

          public int GetMacSize()
          {
               return macSize;
          }

          public void Update(byte input)
          {
               throw new NotImplementedException();
          }

          public void BlockUpdate(byte[] input, int inOff, int len)
          {
               if (len < 0)
               {
                    throw new ArgumentException("Can't have a negative input length!");
               }
               
               if ((inOff + len) % blockSize != 0)
               {
                    throw new NotImplementedException("Partial blocks not supported");
               }

               Check.DataLength(input, inOff, len, "input buffer too short");

               while (len > blockSize)
               {
                    Xor(c, input, inOff, cTemp);
                    
                    engine.ProcessBlock(cTemp, 0, c, 0);
                                        
                    len -= blockSize;
                    inOff += blockSize;
               }

               //Last block
               Xor(c, input, inOff, cTemp);
               Xor(cTemp, kDelta, 0, c);
               engine.ProcessBlock(c, 0, c, 0);               
          }


          private void Xor(byte[] c, byte[] input, int inOff, byte[] xorResult)
          {
               for (int byteIndex = 0; byteIndex < blockSize; byteIndex++)
               {
                    xorResult[byteIndex] = (byte)(c[byteIndex] ^ input[byteIndex + inOff]);
               }
          }

          

          public int DoFinal(byte[] output, int outOff)
          {
               Check.DataLength(output, outOff, macSize, "output buffer too short");

               Array.Copy(c, 0, output, outOff, macSize);

               Reset();

               return macSize;
          }

          public void Reset()
          {
               Array.Clear(c, 0, c.Length);
               Array.Clear(cTemp, 0, cTemp.Length);
               Array.Clear(kDelta, 0, kDelta.Length);
          }
     }
}
