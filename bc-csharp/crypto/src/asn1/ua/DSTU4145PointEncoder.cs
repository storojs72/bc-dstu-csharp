using System;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.UA
{

  /**
   * DSTU4145 encodes points somewhat differently than X9.62
   * It compresses the point to the size of the field element
   */
  public abstract class DSTU4145PointEncoder
  {
      private static ECFieldElement trace(ECFieldElement fe)
      {
          ECFieldElement t = fe;
          for (int i = 1; i < fe.FieldSize; ++i)
          {
              t = t.Square().Add(fe);
          }
          return t;
      }

      /**
       * Solves a quadratic equation <code>z<sup>2</sup> + z = beta</code>(X9.62
       * D.1.6) The other solution is <code>z + 1</code>.
       *
       * @param beta The value to solve the quadratic equation for.
       * @return the solution for <code>z<sup>2</sup> + z = beta</code> or
       *         <code>null</code> if no solution exists.
       */
      private static ECFieldElement solveQuadraticEquation(ECCurve curve, ECFieldElement beta)
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

      public static byte[] encodePoint(ECPoint Q)
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
              if (trace(z).IsOne)
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

      public static ECPoint decodePoint(ECCurve curve, byte[] bytes)
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
          if (!trace(xp).Equals(curve.A))
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
              ECFieldElement z = solveQuadraticEquation(curve, beta);
              if (z != null)
              {
                  if (!trace(z).Equals(k))
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
