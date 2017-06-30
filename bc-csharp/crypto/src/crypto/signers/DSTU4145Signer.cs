using System;
using System.Collections.Generic;
using System.Text;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Crypto.Signers
{
     /*
     * Implementation of DSTU 4145
     * 
     * National ukrainian standard of digital signature based on elliptic curves
     */
     class Dstu4145Signer : IDsa
     {
          private ECKeyParameters operationKey;
          private SecureRandom random;


          public string AlgorithmName
          {
               get { return "DSTU4145"; }
          }

          public void Init(bool forSigning, ICipherParameters parameters)
          {
               if (forSigning)
               {
                    if (parameters is ParametersWithRandom)
                    {
                         ParametersWithRandom rParams = (ParametersWithRandom)parameters;
                         this.random = rParams.Random;
                         parameters = rParams.Parameters;
                    }
                    else
                    {
                         this.random = new SecureRandom();
                    }

                    this.operationKey = (ECPrivateKeyParameters)parameters;
               }
               else
               {
                    this.operationKey = (ECPublicKeyParameters)parameters;
               }
          }

          public BigInteger[] GenerateSignature(byte[] message)
          {
               ECDomainParameters ec = operationKey.Parameters;

               ECCurve curve = ec.Curve;

               ECFieldElement h = Hash2FieldElement(curve, message);

               if (h.IsZero)
               {
                    h = curve.FromBigInteger(BigInteger.One);
               }

               BigInteger n = ec.N;
               BigInteger e, r, s;
               ECFieldElement Fe, y;

               BigInteger d = ((ECPrivateKeyParameters)operationKey).D;

               do
               {
                    do
                    {
                         do
                         {
                              e = GenerateRandomInteger(n, random);
                              Fe = ec.G.Multiply(e).Normalize().AffineXCoord;
                         }
                         while (Fe.IsZero);

                         y = h.Multiply(Fe);
                         r = FieldElement2Integer(n, y);
                    }
                    while (r.SignValue == 0);

                    s = r.Multiply(d).Add(e).Mod(n);

               }
               while (s.SignValue == 0);

               return new BigInteger[] { r, s };
          }

          public bool VerifySignature(byte[] message, BigInteger r, BigInteger s)
          {
               if (r.SignValue <= 0 || s.SignValue <= 0)
               {
                    throw new SignatureException(AlgorithmName + " verification failed. R or S value is negative");
               }

               ECDomainParameters parameters = operationKey.Parameters;

               BigInteger n = parameters.N;

               if (r.CompareTo(n) >= 0 || s.CompareTo(n) >= 0)
               {
                    throw new SignatureException(AlgorithmName + " verification failed. R or S value is greater or equal to modulus");
               }

               ECCurve curve = parameters.Curve;

               ECFieldElement h = Hash2FieldElement(curve, message);

               if (h.IsZero)
               {
                    h = curve.FromBigInteger(BigInteger.One);
               }

               ECPoint R = ECAlgorithms.SumOfTwoMultiplies(parameters.G, s, ((ECPublicKeyParameters)operationKey).Q, r).Normalize();


               if (R.IsInfinity)
               {
                    throw new SignatureException(AlgorithmName + " verification failed. R or S value is bogus");
               }

               ECFieldElement y = h.Multiply(R.AffineXCoord);

               return FieldElement2Integer(n, y).CompareTo(r) == 0;
          }


          private BigInteger FieldElement2Integer(BigInteger modulus, ECFieldElement fieldElement)
          {
               return Truncate(fieldElement.ToBigInteger(), modulus.BitLength - 1);
          }

          private BigInteger Truncate(BigInteger x, int bitLength)
          {
               if (x.BitLength > bitLength)
               {
                    x = x.Mod(BigInteger.One.ShiftLeft(bitLength));
               }
               return x;
          }

          private BigInteger GenerateRandomInteger(BigInteger modulus, SecureRandom random)
          {
               return new BigInteger(modulus.BitLength - 1, random);
          }

          private ECFieldElement Hash2FieldElement(ECCurve curve, byte[] hash)
          {
               byte[] data = new byte[hash.Length];
               Array.Copy(hash, data, hash.Length);
               Array.Reverse(data);

               return curve.FromBigInteger(Truncate(new BigInteger(1, data), curve.FieldSize));
          }
     }






     /**
      * DSTU4145 encodes points somewhat differently than X9.62
      * It compresses the point to the size of the field element
      */
     abstract class Dstu4145PointEncoder
     {
          private static ECFieldElement Trace(ECFieldElement fe)
          {
               ECFieldElement t = fe;
               for (int i = 1; i < fe.FieldSize; ++i)
               {
                    t = t.Square().Add(fe);
               }
               return t;
          }

          /// <summary>
          /// Solves a quadratic equation z^2 + z = beta (X9.62 D.1.6). The other solution is z + 1.
          /// </summary>
          /// <param name="curve"></param>
          /// <param name="beta"></param>
          /// <returns></returns>
          private static ECFieldElement SolveQuadraticEquation(ECCurve curve, ECFieldElement beta)
          {
               if (beta.IsZero)
               {
                    return beta;
               }

               ECFieldElement zeroElement = curve.FromBigInteger(BigInteger.Zero);

               ECFieldElement z = null;
               ECFieldElement gamma = null;

               Random rand = new Random();
               int m = beta.FieldSize;
               do
               {
                    ECFieldElement t = curve.FromBigInteger(new BigInteger(m, rand));
                    z = zeroElement;
                    ECFieldElement w = beta;
                    for (int i = 1; i <= m - 1; i++)
                    {
                         ECFieldElement w2 = w.Square();
                         z = z.Square().Add(w2.Multiply(t));
                         w = w2.Add(beta);
                    }
                    if (!w.IsZero)
                    {
                         return null;
                    }
                    gamma = z.Square().Add(z);
               }
               while (gamma.IsZero);

               return z;
          }



          public static byte[] EncodePoint(ECPoint Q)
          {
               /*if (!Q.isCompressed())
                     Q=new ECPoint.F2m(Q.getCurve(),Q.getX(),Q.getY(),true);

                 byte[] bytes=Q.getEncoded();

                 if (bytes[0]==0x02)
                     bytes[bytes.length-1]&=0xFE;
                 else if (bytes[0]==0x02)
                     bytes[bytes.length-1]|=0x01;

                 return Arrays.copyOfRange(bytes, 1, bytes.length);*/

               Q = Q.Normalize();

               ECFieldElement x = Q.AffineXCoord;

               byte[] bytes = x.GetEncoded();

               if (!x.IsZero)
               {
                    ECFieldElement z = Q.AffineYCoord.Divide(x);
                    if (Trace(z).IsOne)
                    {
                         bytes[bytes.Length - 1] |= 0x01;
                    }
                    else
                    {
                         bytes[bytes.Length - 1] &= 0xFE;
                    }
               }

               return bytes;
          }

          public static ECPoint DecodePoint(ECCurve curve, byte[] bytes)
          {
               /*byte[] bp_enc=new byte[bytes.length+1];
                 if (0==(bytes[bytes.length-1]&0x1))
                     bp_enc[0]=0x02;
                 else
                     bp_enc[0]=0x03;
                 System.arraycopy(bytes, 0, bp_enc, 1, bytes.length);
                 if (!trace(curve.fromBigInteger(new BigInteger(1, bytes))).equals(curve.getA().toBigInteger()))
                     bp_enc[bp_enc.length-1]^=0x01;

                 return curve.decodePoint(bp_enc);*/

               ECFieldElement k = curve.FromBigInteger(BigInteger.ValueOf(bytes[bytes.Length - 1] & 0x1));

               ECFieldElement xp = curve.FromBigInteger(new BigInteger(1, bytes));
               if (!Trace(xp).Equals(curve.A))
               {
                    xp = xp.AddOne();
               }

               ECFieldElement yp = null;
               if (xp.IsZero)
               {
                    yp = curve.B.Sqrt();
               }
               else
               {
                    ECFieldElement beta = xp.Square().Invert().Multiply(curve.B).Add(curve.A).Add(xp);
                    ECFieldElement z = SolveQuadraticEquation(curve, beta);
                    if (z != null)
                    {
                         if (!Trace(z).Equals(k))
                         {
                              z = z.AddOne();
                         }
                         yp = xp.Multiply(z);
                    }
               }

               if (yp == null)
               {
                    throw new ArgumentException("Invalid point compression");
               }

               return curve.ValidatePoint(xp.ToBigInteger(), yp.ToBigInteger());
          }

     }
}
