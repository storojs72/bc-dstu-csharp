using System;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;




namespace Org.BouncyCastle.Crypto.Macs
{
     /// <summary>
     /// Implementation of DSTU7564 mac mode
     /// </summary>
     public class DSTU7564Mac : Dstu7564Digest, IMac
     {
          private int macSize;

          byte[] paddedKey;
          byte[] inversedKey;
          byte[] paddedInput;


          public DSTU7564Mac(int macSizeBits)
               : base(macSizeBits)
          {
               macSize = macSizeBits / 8;
          }



          public void Init(ICipherParameters parameters)
          {
               KeyParameter param = null;

               param = parameters as KeyParameter;

               if (param == null)
               {
                    throw new ArgumentException("Bad parameters passed");
               }
                
               byte[] key = param.GetKey();

               paddedKey = Pad(key, 0, key.Length);

               inversedKey = new byte[key.Length];
               Array.Copy(key, inversedKey, key.Length);


               //Inverse each byte in key
               for (int i = 0; i < inversedKey.Length; i++)
               {
                    inversedKey[i] ^= 0xFF;
               }
          }

          public int GetMacSize()
          {
               return macSize;
          }

          public override void BlockUpdate(byte[] input, int inOff, int len)
          {
               paddedInput = Pad(input, inOff, len);

               byte[] result = new byte[paddedKey.Length + paddedInput.Length + inversedKey.Length];
               Array.Copy(paddedKey, 0, result, 0, paddedKey.Length);
               Array.Copy(paddedInput, 0, result, paddedKey.Length, paddedInput.Length);
               Array.Copy(inversedKey, 0, result, paddedKey.Length + paddedInput.Length, inversedKey.Length);

               result = Pad(result, 0, result.Length);

               int paddedOff = 0;
               int paddedLength = result.Length;
               //Console.WriteLine(Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(result));
               //Console.WriteLine(result.Length);

               while (paddedLength != 0)
               {
                    ProcessBlock(result, paddedOff);
                    //Console.WriteLine();
                    paddedLength -= GetByteLength();
                    paddedOff += GetByteLength();



                    //byte[] stateLine = new byte[ROWS * columns];
                    //int stateLineIndex = 0;
                    //for (int i = 0; i < ROWS; ++i)
                    //{
                    //     for (int j = 0; j < columns; ++j)
                    //     {
                    //          stateLine[stateLineIndex] = state_[i][j];
                    //          stateLineIndex++;
                    //     }
                    //}

                    //Console.WriteLine("block: " + Hex.ToHexString(stateLine));
               }

          }
                   
     }
}
