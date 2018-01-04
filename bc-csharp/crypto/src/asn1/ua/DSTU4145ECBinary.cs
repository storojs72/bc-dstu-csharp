using System;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.Field;

namespace Org.BouncyCastle.Asn1.UA
{

  public class DSTU4145ECBinary
              : Asn1Encodable
  {
      BigInteger version = BigInteger.ValueOf(0);

      DSTU4145BinaryField f;
      DerInteger a;
      Asn1OctetString b;
      DerInteger n;
      Asn1OctetString bp;

      public DSTU4145ECBinary(ECDomainParameters paramsValue)
      {
          ECCurve curve = paramsValue.Curve;
          if (!ECAlgorithms.IsF2mCurve(curve))
          {
              throw new ArgumentException("only binary domain is possible");
          }

          // We always use big-endian in parameter encoding

          IPolynomialExtensionField field = (IPolynomialExtensionField)curve.Field;
          int[] exponents = field.MinimalPolynomial.GetExponentsPresent();
          if (exponents.Length == 3)
          {
              f = new DSTU4145BinaryField(exponents[2], exponents[1]);
          }
          else if (exponents.Length == 5)
          {
              f = new DSTU4145BinaryField(exponents[4], exponents[1], exponents[2], exponents[3]);
          }
          else
          {
              throw new ArgumentException("curve must have a trinomial or pentanomial basis");
          }

          a = new DerInteger(curve.A.ToBigInteger());
          b = new DerOctetString(curve.B.GetEncoded());
          n = new DerInteger(paramsValue.N);
          bp = new DerOctetString(DSTU4145PointEncoder.encodePoint(paramsValue.G));
      }

      private DSTU4145ECBinary(Asn1Sequence seq)
      {
          int index = 0;

          if (seq.GetObjectAt(index) is Asn1TaggedObject)
          {
              Asn1TaggedObject taggedVersion = (Asn1TaggedObject)seq.GetObjectAt(index);
              if (taggedVersion.IsExplicit() && 0 == taggedVersion.TagNo)
              {
                  version = DerInteger.GetInstance(taggedVersion.GetObject()).Value;
                  index++;
              }
              else
              {
                  throw new ArgumentException("object parse error");
              }
          }
          f = DSTU4145BinaryField.GetInstance(seq.GetObjectAt(index));
          index++;
          a = DerInteger.GetInstance(seq.GetObjectAt(index));
          index++;
          b = Asn1OctetString.GetInstance(seq.GetObjectAt(index));
          index++;
          n = DerInteger.GetInstance(seq.GetObjectAt(index));
          index++;
          bp = Asn1OctetString.GetInstance(seq.GetObjectAt(index));
      }

      public static DSTU4145ECBinary GetInstance(Object obj)
      {
          if (obj is DSTU4145ECBinary)
          {
              return (DSTU4145ECBinary)obj;
          }

          if (obj != null)
          {
              return new DSTU4145ECBinary(Asn1Sequence.GetInstance(obj));
          }

          return null;
      }

      public DSTU4145BinaryField getField()
      {
          return f;
      }

      public BigInteger getA()
      {
          return a.Value;
      }

      public byte[] getB()
      {
          return (byte[])b.GetOctets().Clone();
      }

      public BigInteger getN()
      {
          return n.Value;
      }

      public byte[] getG()
      {
          return (byte[])bp.GetOctets().Clone();
      }

      /**
       * ECBinary  ::= SEQUENCE {
       * version          [0] EXPLICIT INTEGER    DEFAULT 0,
       * f     BinaryField,
       * a    INTEGER (0..1),
       * b    OCTET STRING,
       * n    INTEGER,
       * bp    OCTET STRING}
       */
      public override Asn1Object ToAsn1Object()
      {

          Asn1EncodableVector v = new Asn1EncodableVector();

          if (0 != version.CompareTo(BigInteger.ValueOf(0)))
          {
              v.Add(new DerTaggedObject(true, 0, new DerInteger(version)));
          }
          v.Add(f);
          v.Add(a);
          v.Add(b);
          v.Add(n);
          v.Add(bp);

          return new DerSequence(v);
      }

  }
}
