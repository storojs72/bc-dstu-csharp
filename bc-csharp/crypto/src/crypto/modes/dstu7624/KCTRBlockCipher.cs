using System;

using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Modes
{
     /**
     * implements a Gamming or Counter (CTR) mode on top of a DSTU 7624 block cipher.
     */
     public class KCtrBlockCipher : IBlockCipher
     {
          private byte[] IV;
          private byte[] ofbV;
          private byte[] ofbOutV;
          private bool encrypting;

          private readonly int blockSize;
          private readonly IBlockCipher cipher;
          
          /**
          * Basic constructor.
          *
          * @param cipher the block cipher to be used as the basis of the
          * feedback mode.
          */
          public KCtrBlockCipher(IBlockCipher cipher)
          {
               this.cipher = cipher;
               this.IV = new byte[cipher.GetBlockSize()];
               this.blockSize = cipher.GetBlockSize();

               this.ofbV = new byte[cipher.GetBlockSize()];
               this.ofbOutV = new byte[cipher.GetBlockSize()];

          }

          /**
          * return the underlying block cipher that we are wrapping.
          *
          * @return the underlying block cipher that we are wrapping.
          */
          public IBlockCipher GetUnderlyingCipher()
          {
               return cipher;
          }

          /**
          * Initialise the cipher and, possibly, the initialisation vector (IV).
          * If an IV isn't passed as part of the parameter, the IV will be all zeros.
          * An IV which is too short is handled in FIPS compliant fashion.
          *
          * @param forEncryption if true the cipher is initialised for
          *  encryption, if false for decryption.
          * @param param the key and other data required by the cipher.
          * @exception ArgumentException if the parameters argument is
          * inappropriate.
          */
          public void Init(
              bool forEncryption,
              ICipherParameters parameters)
          {
               this.encrypting = forEncryption;
               if (parameters is ParametersWithIV)
               {
                    ParametersWithIV ivParam = (ParametersWithIV)parameters;
                    byte[] iv = ivParam.GetIV();
                    int diff = IV.Length - iv.Length;
                    Array.Copy(iv, 0, IV, diff, iv.Length);
                    Array.Clear(IV, 0, diff);

                    parameters = ivParam.Parameters;
               }
               Reset();

               // if it's null, key is to be reused.
               if (parameters != null)
               {
                    cipher.Init(true, parameters);
                    cipher.ProcessBlock(IV, 0, ofbV, 0);

                    //Console.WriteLine("OFB :" + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(ofbV));
               }
          }

          /**
          * return the algorithm name and mode.
          *
          * @return the name of the underlying algorithm followed by "/KCTR"
          * and the block size in bits.
          */
          public string AlgorithmName
          {
               get { return cipher.AlgorithmName + "/KCTR"; }
          }

          public bool IsPartialBlockOkay
          {
               get { return true; }
          }

          /**
          * return the block size we are operating at.
          *
          * @return the block size we are operating at (in bytes).
          */
          public int GetBlockSize()
          {
               return cipher.GetBlockSize();
          }

          /**
          * Process one block of input from the array in and write it to
          * the out array.
          *
          * @param in the array containing the input data.
          * @param inOff offset into the in array the data starts at.
          * @param out the array the output data will be copied into.
          * @param outOff the offset into the out array the output will start at.
          * @exception DataLengthException if there isn't enough data in in, or
          * space in out.
          * @exception InvalidOperationException if the cipher isn't initialised.
          * @return the number of bytes processed and produced.
          */
          public int ProcessBlock(
              byte[] input,
              int inOff,
              byte[] output,
              int outOff)
          {                   
               Check.DataLength(input, inOff, GetBlockSize(), "input buffer too short");
               Check.OutputLength(output, outOff, GetBlockSize(), "output buffer too short");
                              
               ofbV[0]++;
               
               cipher.ProcessBlock(ofbV, 0, ofbOutV, 0);

               //
               // XOR the ofbV with the plaintext producing the ciphertext
               //
               for (int i = 0; i < blockSize; i++)
               {
                    output[outOff + i] = (byte)(ofbOutV[i] ^ input[inOff + i]);
               }

               return blockSize;
          }



          /**
          * reset the chaining vector back to the IV and reset the underlying
          * cipher.
          */
          public void Reset()
          {
               Array.Copy(IV, 0, ofbV, 0, IV.Length);
               cipher.Reset();
          }
     }
}
