using System;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.UA
{

  public class DSTU4145Params
        : Asn1Encodable
  {
      private static byte[] DEFAULT_DKE = {
          (byte)0xa9, (byte)0xd6, (byte)0xeb, 0x45, (byte)0xf1, 0x3c, 0x70, (byte)0x82,
          (byte)0x80, (byte)0xc4, (byte)0x96, 0x7b, 0x23, 0x1f, 0x5e, (byte)0xad,
          (byte)0xf6, 0x58, (byte)0xeb, (byte)0xa4, (byte)0xc0, 0x37, 0x29, 0x1d,
          0x38, (byte)0xd9, 0x6b, (byte)0xf0, 0x25, (byte)0xca, 0x4e, 0x17,
          (byte)0xf8, (byte)0xe9, 0x72, 0x0d, (byte)0xc6, 0x15, (byte)0xb4, 0x3a,
          0x28, (byte)0x97, 0x5f, 0x0b, (byte)0xc1, (byte)0xde, (byte)0xa3, 0x64,
          0x38, (byte)0xb5, 0x64, (byte)0xea, 0x2c, 0x17, (byte)0x9f, (byte)0xd0,
          0x12, 0x3e, 0x6d, (byte)0xb8, (byte)0xfa, (byte)0xc5, 0x79, 0x04};


      private DerObjectIdentifier namedCurve;
      private DSTU4145ECBinary ecbinary;
      private byte[] dke = DEFAULT_DKE;

      public DSTU4145Params(DerObjectIdentifier namedCurve)
      {
          this.namedCurve = namedCurve;
      }

      public DSTU4145Params(DerObjectIdentifier namedCurve, byte[] dke)
      {
          this.namedCurve = namedCurve;
          this.dke = (byte[])dke.Clone();
      }

      public DSTU4145Params(DSTU4145ECBinary ecbinary)
      {
          this.ecbinary = ecbinary;
      }

      public bool isNamedCurve()
      {
          return namedCurve != null;
      }

      public DSTU4145ECBinary getECBinary()
      {
          return ecbinary;
      }

      public byte[] getDKE()
      {
          return dke;
      }

      public static byte[] getDefaultDKE()
      {
          return DEFAULT_DKE;
      }

      public DerObjectIdentifier getNamedCurve()
      {
          return namedCurve;
      }

      public static DSTU4145Params GetInstance(Object obj)
      {
          if (obj is DSTU4145Params)
          {
              return (DSTU4145Params)obj;
          }

          if (obj != null)
          {
              Asn1Sequence seq = Asn1Sequence.GetInstance(obj);
              DSTU4145Params paramsValue;

              if (seq.GetObjectAt(0) is DerObjectIdentifier)
              {
                  paramsValue = new DSTU4145Params(DerObjectIdentifier.GetInstance(seq.GetObjectAt(0)));
              }
              else
              {
                  paramsValue = new DSTU4145Params(DSTU4145ECBinary.GetInstance(seq.GetObjectAt(0)));
              }

              if (seq.Size == 2)
              {
                  paramsValue.dke = Asn1OctetString.GetInstance(seq.GetObjectAt(1)).GetOctets();
                  if (paramsValue.dke.Length != DSTU4145Params.DEFAULT_DKE.Length)
                  {
                      throw new ArgumentException("object parse error");
                  }
              }

              return paramsValue;
          }

          throw new ArgumentException("object parse error");
      }

      public override Asn1Object ToAsn1Object()
      {
          Asn1EncodableVector v = new Asn1EncodableVector();

          if (namedCurve != null)
          {
              v.Add(namedCurve);
          }
          else
          {
              v.Add(ecbinary);
          }

          if (!Arrays.AreEqual(dke, DEFAULT_DKE))
          {
              v.Add(new DerOctetString(dke));
          }

          return new DerSequence(v);
      }
  }
}
