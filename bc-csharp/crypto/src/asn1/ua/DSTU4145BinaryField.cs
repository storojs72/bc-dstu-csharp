using System;

namespace Org.BouncyCastle.Asn1.UA
{
  public class DSTU4145BinaryField: Asn1Encodable
  {

      private int m, k, j, l;

      private DSTU4145BinaryField(Asn1Sequence seq)
      {
          m = DerInteger.GetInstance(seq.GetObjectAt(0)).PositiveValue.IntValue;

          if (seq.GetObjectAt(1) is DerInteger)
          {
              k = ((DerInteger)seq.GetObjectAt(1)).PositiveValue.IntValue;
          }
          else if (seq.GetObjectAt(1) is Asn1Sequence)
          {
              Asn1Sequence coefs = Asn1Sequence.GetInstance(seq.GetObjectAt(1));

              k = DerInteger.GetInstance(coefs.GetObjectAt(0)).PositiveValue.IntValue;
              j = DerInteger.GetInstance(coefs.GetObjectAt(1)).PositiveValue.IntValue;
              l = DerInteger.GetInstance(coefs.GetObjectAt(2)).PositiveValue.IntValue;
          }
          else
          {
              throw new ArgumentException("object parse error");
          }
      }

      public static DSTU4145BinaryField GetInstance(Object obj)
      {
          if (obj is DSTU4145BinaryField)
          {
              return (DSTU4145BinaryField)obj;
          }

          if (obj != null)
          {
              return new DSTU4145BinaryField(Asn1Sequence.GetInstance(obj));
          }

          return null;
      }

      public DSTU4145BinaryField(int m, int k1, int k2, int k3)
      {
          this.m = m;
          this.k = k1;
          this.j = k2;
          this.l = k3;
      }

      public int getM()
      {
          return m;
      }

      public int getK1()
      {
          return k;
      }

      public int getK2()
      {
          return j;
      }

      public int getK3()
      {
          return l;
      }

      public DSTU4145BinaryField(int m, int k)
      {
          this.m = m;
          this.k = k;
          this.j = 0;
          this.l = 0;
      }

      /**
       * BinaryField ::= SEQUENCE {
       * M INTEGER,
       * CHOICE {Trinomial,    Pentanomial}
       * Trinomial::= INTEGER
       * Pentanomial::= SEQUENCE {
       * k INTEGER,
       * j INTEGER,
       * l INTEGER}
       */
      public override Asn1Object ToAsn1Object()
      {

          Asn1EncodableVector v = new Asn1EncodableVector();

          v.Add(new DerInteger(m));
          if (j == 0) //Trinomial
          {
              v.Add(new DerInteger(k));
          }
          else
          {
              Asn1EncodableVector coefs = new Asn1EncodableVector();
              coefs.Add(new DerInteger(k));
              coefs.Add(new DerInteger(j));
              coefs.Add(new DerInteger(l));

              v.Add(new DerSequence(coefs));
          }

          return new DerSequence(v);
      }

  }
}
