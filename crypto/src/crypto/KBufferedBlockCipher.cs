using System;
using System.Diagnostics;

using System.Collections;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;




namespace Org.BouncyCastle.Crypto
{
     /**
     * Create a buffered block cipher without padding (as CFB mode in DSTU 7624 define). 
     * Bitwise encryption and Bitwise padding (Appendix B) are also added.
     *
     * @param cipher the underlying block cipher this buffering object wraps.
     * false otherwise.
     */
     public class KBufferedBlockCipher : BufferedBlockCipher
     {
          private byte[] temp;
                            
          public KBufferedBlockCipher(
               IBlockCipher cipher)
          {
               if (cipher == null)
                    throw new ArgumentNullException("cipher");

               this.cipher = cipher;
               buf = new byte[cipher.GetBlockSize()];
               
               bufOff = 0;

               temp = new byte[cipher.GetBlockSize()];
                              
          }

          public override int DoFinal(byte[] output, int outOff)
          {
               try
               {
                    if (bufOff != 0)
                    {
                         Check.DataLength(!cipher.IsPartialBlockOkay, "data not block size aligned");
                         Check.OutputLength(output, outOff, bufOff, "output buffer too short for DoFinal()");

                        
                         Array.Copy(buf, 0, temp, temp.Length - bufOff, bufOff);
                                               
                         cipher.ProcessBlock(temp, 0, buf, 0);

                         //Console.WriteLine("buf: " + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(buf));
                         
                         Array.Copy(buf, buf.Length - bufOff, output, outOff, bufOff);

                         //Console.WriteLine("output: " + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(output));
                    }

                    return bufOff;
               }
               finally
               {
                    Reset();
               }
          }



          
          /// <summary>
          /// Bitwise encryption
          /// </summary>
          /// <param name="input"></param>
          /// <param name="inOff"></param>
          /// <param name="length"></param>
          /// <param name="output"></param>
          /// <param name="outOff"></param>
          /// <param name="N">input length in bits to encrypt</param>
          public void ProcessBits(
               byte[] input,
               int inOff,
               int length,
               byte[] output,
               int outOff,
               int N)
          {
                                                                           
               //int bytesWritten = ProcessBytes(input, inOff, length, output, outOff);
               ////Console.WriteLine("input: " + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(input));
               ////Console.WriteLine("output: " + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(output));
               ////Console.WriteLine(bufOff);
               ////Console.WriteLine("buffer: " + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(buf));

               //int significantBits = N % 8;

               //Console.WriteLine(significantBits);
               ////DoFinal
               //try
               //{         
                    
               //     if (bufOff != 0)
               //     {
               //          Check.DataLength(!cipher.IsPartialBlockOkay, "data not block size aligned");
               //          Check.OutputLength(output, outOff, bufOff, "output buffer too short for DoFinal()");

               //          Console.WriteLine("buf: " + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(buf));

               //          //Shifting last byte left on number of significant bits
               //          buf[bufOff - 1] <<= 4;

               //          Console.WriteLine("buf: " + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(buf));

               //          cipher.ProcessBlock(buf, 0, buf, 0);

               //          Console.WriteLine("buf: " + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(buf));

                         

               //          //Console.WriteLine("buf: " + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(buf));

               //          //Console.WriteLine(significantBits);
               //          //Console.WriteLine(maskLookUp[8 - significantBits]);

               //          //Masking insignificant bits in last byte
               //          //buf[bufOff - 1] &= maskLookUp[8 - significantBits];
               //          buf[bufOff - 1] &= 0xf0;

               //          //Console.WriteLine("buf: " + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(buf));

               //          //Shifting last byte back
               //          buf[bufOff - 1] >>= 4;

               //          //Console.WriteLine("buf: " + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(buf));
                         
               //          Array.Copy(buf, 0, output, bytesWritten, bufOff);

               //          //Console.WriteLine("output: " + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(output));
               //     }
               //}
               //finally
               //{
               //     Reset();
               //}   


               int bytesWritten = ProcessBytes(input, inOff, length, output, outOff);

               //Console.WriteLine("output: " + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(output));

               int N_ = N % (cipher.GetBlockSize() * 8);
                   
               try
               {
                    if (bufOff != 0)
                    {
                         Check.DataLength(!cipher.IsPartialBlockOkay, "data not block size aligned");
                         Check.OutputLength(output, outOff, bufOff, "output buffer too short for DoFinal()");
                         
                         Array.Clear(temp, 0, temp.Length);
                         cipher.ProcessBlock(temp, 0, temp, 0);
                         //Console.WriteLine("gamma: " + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(temp));
                         
                        
                         BitArray bits = new BitArray(temp);
                         bits.FixLength(N_);
                         byte[] gamma = bits.GetBytes();


                         bits = new BitArray(buf);
                         bits.FixLength(N_);
                         byte[] lastBlockBytes = bits.GetBytes();


                         //Console.WriteLine("gamma: " + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(gamma));
                         //Console.WriteLine("lastBlockBytes: " + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(lastBlockBytes));

                         for (int i = 0; i < lastBlockBytes.Length; i++)
                         {
                              lastBlockBytes[i] ^= gamma[i];
                         }

                         bits = new BitArray(lastBlockBytes);

                        
                         //Shifting non-significant bits
                         bits = bits.ShiftLeft(8 - N % 8);
                                                  
                         //Console.WriteLine(bits.ToString());

                         lastBlockBytes = bits.GetBytes();
                         
                         //Console.WriteLine("lastBlockBytes: " + Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(lastBlockBytes));

                         Array.Copy(lastBlockBytes, 0, output, bytesWritten, lastBlockBytes.Length);
                    }
               }

               finally
               {
                    Reset();
               }  

              
          }


          [Serializable]
          private class BitArray
          {
               private ArrayList _Bits = new ArrayList();
               
               public BitArray()
               {

               }

               public BitArray(int length)
               {
                    AddBlock(length, false);
               }

               public BitArray(byte[] bits)
               {
                    string st;
                    foreach (byte b in bits)
                    {
                         st = FixLength(Convert.ToString(b, 2), 8);
                         AddBits(st);
                    }
               }

               private string FixLength(string num, int length)
               {
                    while (num.Length < length)
                         num = num.Insert(0, "0");
                    return num;
               }
               private void AddBits(string bits)
               {
                    foreach (char ch in bits)
                    {
                         if (ch == '0')
                              _Bits.Add(false);
                         else if (ch == '1')
                              _Bits.Add(true);
                         else
                              throw (new ArgumentException("bits Contain none 0 1 character"));
                    }
               }
               private void AddBlock(int length, bool Value)
               {
                    for (int i = 0; i < length; i++)
                         _Bits.Add(Value);
               }
               /// <summary>
               /// Set the bit at the specific position in System.Collection.JIBitArray
               /// </summary>
               /// <param name="index">The zero-based index of the bit to set</param>
               /// <param name="Value">The Boolean value to assign to the bit</param>
               public void Set(int index, bool Value)
               {
                    _Bits[index] = Value;
               }

               /// <summary>
               /// Retrieves a SubJIBitArray from this instance. The SubJIBitArray start at the 
               /// specified bit position and has specified length
               /// </summary>
               /// <param name="index">The index of the start of SubJIBitArray</param>
               /// <param name="length">The number of bits in SubJIBitArray</param>
               /// <returns></returns>
               public BitArray SubBitArray(int index, int length)
               {
                    BitArray RArray = new BitArray(length);
                    int c = 0;
                    for (int i = index; i < index + length; i++)
                         RArray.Set(c++, (bool)_Bits[i]);
                    return RArray;
               }


               /// <summary>
               /// Convert current System.Collections.JIBitArray to a byte array
               /// </summary>
               /// <returns></returns>
               public byte[] GetBytes()
               {
                    int ArrayBound = (int)System.Math.Ceiling((double)this._Bits.Count / 8);
                    byte[] Bits = new byte[ArrayBound];
                    BitArray Temp = new BitArray();
                    Temp._Bits = this._Bits;
                    Temp = FixLength(Temp, ArrayBound * 8);

                    for (int i = 0; i < Temp._Bits.Count; i += 8)
                    {
                         Bits[i / 8] = Convert.ToByte(Temp.SubBitArray(i, 8).ToString(), 2);
                    }
                    return Bits;
               }


               /// <summary>
               /// Insert enough zero at the beginning of the specified System.Collections.JIBitArray to 
               /// make it's length to specified length
               /// </summary>
               /// <param name="Value">The System.Collections.JIBitArray with wich to insert zero to begining</param>
               /// <param name="length">The number of bits of Value after inserting</param>
               /// <returns></returns>
               public static BitArray FixLength(BitArray Value, int length)
               {
                    if (length < Value._Bits.Count)
                         throw (new ArgumentException("length must be equal or greater than Bits.Length"));
                    while (Value._Bits.Count < length)
                         Value._Bits.Insert(0, false);
                    return Value;
               }

               /// <summary>
               /// Shift the bits of current System.Collections.JIBitArray as specified number to 
               /// left
               /// </summary>
               /// <param name="count">Specific number to shift left</param>
               /// <returns></returns>
               public BitArray ShiftLeft(int count)
               {
                    BitArray RArray = new BitArray();
                    RArray._Bits = this._Bits;

                    for (int i = 0; i < count; i++)
                    {
                         RArray._Bits.RemoveAt(0);
                         RArray._Bits.Add(false);

                    }
                    return RArray;
               }



               /// <summary>
               /// Convert current System.Collections.JIBitArray to binary string
               /// </summary>
               /// <returns></returns>
               public override string ToString()
               {
                    string rt = string.Empty;
                    foreach (bool b in _Bits)
                    {
                         if (b == false)
                              rt += '0';
                         else
                              rt += '1';
                    }
                    return rt;
               }

               internal void FixLength(int N)
               {
                    _Bits.RemoveRange(N, _Bits.Count - N);
               }

               /// <summary>
               /// Remove zero's of begining of current System.Collections.JIBitArray
               /// </summary>
               /// <returns></returns>
               public BitArray RemoveBeginingZeros()
               {
                    BitArray RArray = new BitArray();
                    RArray._Bits = this._Bits;
                    while (RArray._Bits.Count != 0 && (bool)RArray._Bits[0] == false)
                         RArray._Bits.RemoveAt(0);
                    return RArray;
               }
          }
     }
          
}
