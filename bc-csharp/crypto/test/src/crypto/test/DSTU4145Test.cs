using System;
using System.Collections.Generic;
using System.Text;

using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Org.BouncyCastle.Crypto.Tests
{
     public class Dstu4145Test : SimpleTest
     {
          public override string Name
          {
               get { return "DSTU4145"; }
          }

          public static void Main(String[] args)
          {
               Dstu4145Test tests = new Dstu4145Test();
               tests.PerformTest();
          }

          public override void PerformTest()
          {
               ITestResult result;

               result = Test163();
               if (!result.IsSuccessful())
               {
                    Console.WriteLine(result);
                    return;
               }

               result = Test173();
               if (!result.IsSuccessful())
               {
                    Console.WriteLine(result);
                    return;
               }

               result = Test283();
               if (!result.IsSuccessful())
               {
                    Console.WriteLine(result);
                    return;
               }

               result = Test431();
               if (!result.IsSuccessful())
               {
                    Console.WriteLine(result);
                    return;
               }

               result = TestTruncation();
               if (!result.IsSuccessful())
               {
                    Console.WriteLine(result);
                    return;
               }

               result = TestDstu4145PointEncoding();
               if (!result.IsSuccessful())
               {
                    Console.WriteLine(result);
                    return;
               }

               Console.WriteLine(result);
          }

          private SimpleTestResult TestDstu4145PointEncoding()
          {
               F2mCurve curve = new F2mCurve(257, 12, 0, 0, BigInteger.Zero, new BigInteger("1CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10", 16));
               ECPoint P = curve.CreatePoint(new BigInteger("02A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7", 16), new BigInteger("10686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF", 16));
               BigInteger n = new BigInteger("800000000000000000000000000000006759213AF182E987D3E17714907D470D", 16);

               ECDomainParameters domain = new ECDomainParameters(curve, P, n);

               byte[] hash = Hex.Decode("5D7ABB9C8547FD918C14BB3F3F854E0F2287AB36E53E7E1F26AA7C93CB951C8D");

               byte[] encodedPoint = Hex.Decode("00DC2496C45E484D63D4FE2F1BCA948A2B2E0FA68E4715E44D85600034CF4EB5C5");

                              
               BigInteger r = new BigInteger("5C24783F710861AEE269F4025F68AF3AA1661D2A7FF0DA41E0084CF931E07954", 16);
               BigInteger s = new BigInteger("2C33DE0A65044521EBDC12C812B1E5E4ADE74C69DCFB5B100C1707081B098B01", 16);
             
               ECPoint Q = Dstu4145PointEncoder.DecodePoint(curve, encodedPoint);
               
               ECPublicKeyParameters pubKey = new ECPublicKeyParameters(Q, domain);

               Dstu4145Signer dstuSigner = new Dstu4145Signer();
               dstuSigner.Init(false, pubKey);
               if (!dstuSigner.VerifySignature(hash, r, s))
               {
                    return new SimpleTestResult(false, Name + " test point encoding: verification failed");
               }
               
               return new SimpleTestResult(true, Name + ": Okay");
          }

          private SimpleTestResult TestTruncation()
          {
               SecureRandom random = FixedSecureRandom.From(Hex.Decode("0000C4224DBBD800988DBAA39DE838294C345CDA5F5929D1174AA8D9340A5E79D10ACADE6B53CF873E7301A3871C2073AD75AB530457"));

               // use extra long "hash" with set bits ...
               byte[] hash = Hex.Decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");


               BigInteger r = new BigInteger("6bb5c0cb82e5067485458ebfe81025f03b687c63a27", 16);
               BigInteger s = new BigInteger("34d6b1868969b86ecf934167c8fe352c63d1074bd", 16);

               F2mCurve curve = new F2mCurve(173, 1, 2, 10, BigInteger.Zero, new BigInteger("108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9", 16));
               ECPoint P = curve.CreatePoint(new BigInteger("BE6628EC3E67A91A4E470894FBA72B52C515F8AEE9", 16), new BigInteger("D9DEEDF655CF5412313C11CA566CDC71F4DA57DB45C", 16));
               BigInteger n = new BigInteger("800000000000000000000189B4E67606E3825BB2831", 16);

               BigInteger d = new BigInteger("955CD7E344303D1034E66933DC21C8044D42ADB8", 16);
               ECPoint Q = P.Multiply(d).Negate();

               ECDomainParameters domain = new ECDomainParameters(curve, P, n);
               ICipherParameters privKey = new ParametersWithRandom(new ECPrivateKeyParameters(d, domain), random);
               ECPublicKeyParameters pubKey = new ECPublicKeyParameters(Q, domain);

               Dstu4145Signer dstuSigner = new Dstu4145Signer();
               dstuSigner.Init(true, privKey);
               BigInteger[] rs = dstuSigner.GenerateSignature(hash);

               if (rs[0].CompareTo(r) != 0)
               {
                    return new SimpleTestResult(false, Name + " test truncation: expected r: " + r.ToString(16) + " got r:" + rs[0].ToString(16));
               }

               if (rs[1].CompareTo(s) != 0)
               {
                    return new SimpleTestResult(false, Name + " test truncation: expected s: " + s.ToString(16) + " got s:" + rs[1].ToString(16));
               }

               dstuSigner.Init(false, pubKey);
               if (!dstuSigner.VerifySignature(hash, r, s))
               {
                    return new SimpleTestResult(false, Name + " test truncation: verification failed");
               }

               return new SimpleTestResult(true, Name + ": Okay");
          }

          private SimpleTestResult Test431()
          {
               SecureRandom random = FixedSecureRandom.From(Hex.Decode("0000C4224DBBD800988DBAA39DE838294C345CDA5F5929D1174AA8D9340A5E79D10ACADE6B53CF873E7301A3871C2073AD75AB530457"));
               byte[] hash = Hex.Decode("0137187EA862117EF1484289470ECAC802C5A651FDA8");
               Array.Reverse(hash);


               BigInteger r = new BigInteger("1911fefb1f494bebcf8dffdf5276946ff9c9f662192ee18c718db47310a439c784fe07577b16e1edbe16179876e0792a634f1c9c3a2e", 16);
               BigInteger s = new BigInteger("3852170ee801c2083c52f1ea77b987a5432acecd9c654f064e87bf179e0a397151edbca430082e43bd38a67b55424b5bbc7f2713f620", 16);

               F2mCurve curve = new F2mCurve(431, 1, 3, 5, BigInteger.One, new BigInteger("3CE10490F6A708FC26DFE8C3D27C4F94E690134D5BFF988D8D28AAEAEDE975936C66BAC536B18AE2DC312CA493117DAA469C640CAF3", 16));
               ECPoint P = curve.CreatePoint(new BigInteger("9548BCDF314CEEEAF099C780FFEFBF93F9FE5B5F55547603C9C8FC1A2774170882B3BE35E892C6D4296B8DEA282EC30FB344272791", 16), new BigInteger("4C6CBD7C62A8EEEFDE17A8B5E196E49A22CE6DE128ABD9FBD81FA4411AD5A38E2A810BEDE09A7C6226BCDCB4A4A5DA37B4725E00AA74", 16));
               BigInteger n = new BigInteger("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF", 16);

               BigInteger d = new BigInteger("D0F97354E314191FD773E2404F478C8AEE0FF5109F39E6F37D1FEEC8B2ED1691D84C9882CC729E716A71CC013F66CAC60E29E22C", 16);
               ECPoint Q = P.Multiply(d).Negate();
                              
               ECDomainParameters domain = new ECDomainParameters(curve, P, n);
               ICipherParameters privKey = new ParametersWithRandom(new ECPrivateKeyParameters(d, domain), random);
               ECPublicKeyParameters pubKey = new ECPublicKeyParameters(Q, domain);

               

               Dstu4145Signer dstuSigner = new Dstu4145Signer();
               dstuSigner.Init(true, privKey);
               BigInteger[] rs = dstuSigner.GenerateSignature(hash);

               if (rs[0].CompareTo(r) != 0)
               {
                    return new SimpleTestResult(false, Name + " test 431: expected r: " + r.ToString(16) + " got r:" + rs[0].ToString(16));
               }

               if (rs[1].CompareTo(s) != 0)
               {
                    return new SimpleTestResult(false, Name + " test 431: expected s: " + s.ToString(16) + " got s:" + rs[1].ToString(16));
               }

               dstuSigner.Init(false, pubKey);
               if (!dstuSigner.VerifySignature(hash, r, s))
               {
                    return new SimpleTestResult(false, Name + " test 431: verification failed");
               }

               return new SimpleTestResult(true, Name + ": Okay");
          }
                   
          private SimpleTestResult Test283()
          {
               SecureRandom random = FixedSecureRandom.From(Hex.Decode("00000000245383CB3AD41BF30F5F7E8FBA858509B2D5558C92D539A6D994BFA98BC6940E"));
               byte[] hash = Hex.Decode("0137187EA862117EF1484289470ECAC802C5A651FDA8");
               Array.Reverse(hash);


               BigInteger r = new BigInteger("12a5edcc38d92208ff23036d75b000c7e4bc0f9af2d40b35f15d6fd15e01234e67781a8", 16);
               BigInteger s = new BigInteger("2de0775577f75b643cf5afc80d4fe10b21100690f17e2cab7bdc9b50ec87c5727aeb515", 16);

               F2mCurve curve = new F2mCurve(283, 5, 7, 12, BigInteger.One, new BigInteger("27B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5", 16));
               ECPoint P = curve.CreatePoint(new BigInteger("4D95820ACE761110824CE425C8089129487389B7F0E0A9D043DDC0BB0A4CC9EB25", 16), new BigInteger("954C9C4029B2C62DE35C2B9C2A164984BF1101951E3A68ED03DF234DDE5BB2013152F2", 16));
               BigInteger n = new BigInteger("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307", 16);

               BigInteger d = new BigInteger("B844EEAF15213E4BAD4FB84796D68F2448DB8EB7B4621EC0D51929874892C43E", 16);
               ECPoint Q = P.Multiply(d).Negate();

               ECDomainParameters domain = new ECDomainParameters(curve, P, n);
               ICipherParameters privKey = new ParametersWithRandom(new ECPrivateKeyParameters(d, domain), random);
               ECPublicKeyParameters pubKey = new ECPublicKeyParameters(Q, domain);

               Dstu4145Signer dstuSigner = new Dstu4145Signer();
               dstuSigner.Init(true, privKey);
               BigInteger[] rs = dstuSigner.GenerateSignature(hash);

               if (rs[0].CompareTo(r) != 0)
               {
                    return new SimpleTestResult(false, Name + " test 283: expected r: " + r.ToString(16) + " got r:" + rs[0].ToString(16));
               }

               if (rs[1].CompareTo(s) != 0)
               {
                    return new SimpleTestResult(false, Name + " test 283: expected s: " + s.ToString(16) + " got s:" + rs[1].ToString(16));
               }

               dstuSigner.Init(false, pubKey);
               if (!dstuSigner.VerifySignature(hash, r, s))
               {
                    return new SimpleTestResult(false, Name + " test 283: verification failed");
               }

               return new SimpleTestResult(true, Name + ": Okay");
          }

          private SimpleTestResult Test173()
          {
               SecureRandom random = FixedSecureRandom.From(Hex.Decode("0000137449348C1249971759D99C252FFE1E14D8B31F"));
               byte[] hash = Hex.Decode("0137187EA862117EF1484289470ECAC802C5A651FDA8");
               Array.Reverse(hash);


               BigInteger r = new BigInteger("13ae89746386709cdbd237cc5ec20ca30004a82ead8", 16);
               BigInteger s = new BigInteger("3597912cdd093b3e711ccb74a79d3c4ab4c7cccdc60", 16);

               F2mCurve curve = new F2mCurve(173, 1, 2, 10, BigInteger.Zero, new BigInteger("108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9", 16));
               ECPoint P = curve.CreatePoint(new BigInteger("BE6628EC3E67A91A4E470894FBA72B52C515F8AEE9", 16), new BigInteger("D9DEEDF655CF5412313C11CA566CDC71F4DA57DB45C", 16));
               BigInteger n = new BigInteger("800000000000000000000189B4E67606E3825BB2831", 16);

               BigInteger d = new BigInteger("955CD7E344303D1034E66933DC21C8044D42ADB8", 16);
               ECPoint Q = P.Multiply(d).Negate();

               ECDomainParameters domain = new ECDomainParameters(curve, P, n);
               ICipherParameters privKey = new ParametersWithRandom(new ECPrivateKeyParameters(d, domain), random);
               ECPublicKeyParameters pubKey = new ECPublicKeyParameters(Q, domain);

               Dstu4145Signer dstuSigner = new Dstu4145Signer();
               dstuSigner.Init(true, privKey);
               BigInteger[] rs = dstuSigner.GenerateSignature(hash);

               if (rs[0].CompareTo(r) != 0)
               {
                    return new SimpleTestResult(false, Name + " test 173: expected r: " + r.ToString(16) + " got r:" + rs[0].ToString(16));
               }

               if (rs[1].CompareTo(s) != 0)
               {
                    return new SimpleTestResult(false, Name + " test 173: expected s: " + s.ToString(16) + " got s:" + rs[1].ToString(16));
               }

               dstuSigner.Init(false, pubKey);
               if (!dstuSigner.VerifySignature(hash, r, s))
               {
                    return new SimpleTestResult(false, Name + " test 173: verification failed");
               }

               return new SimpleTestResult(true, Name + ": Okay");
          }

          private SimpleTestResult Test163()
          {
               SecureRandom random = FixedSecureRandom.From(Hex.Decode("01025e40bd97db012b7a1d79de8e12932d247f61c6"));
               byte[] hash = Hex.Decode("09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff");
               Array.Reverse(hash);


               BigInteger r = new BigInteger("274ea2c0caa014a0d80a424f59ade7a93068d08a7", 16);
               BigInteger s = new BigInteger("2100d86957331832b8e8c230f5bd6a332b3615aca", 16);

               F2mCurve curve = new F2mCurve(163, 3, 6, 7, BigInteger.One , new BigInteger("5FF6108462A2DC8210AB403925E638A19C1455D21", 16));
               ECPoint P = curve.CreatePoint(new BigInteger("72d867f93a93ac27df9ff01affe74885c8c540420", 16), new BigInteger("0224a9c3947852b97c5599d5f4ab81122adc3fd9b", 16));
               BigInteger n = new BigInteger("400000000000000000002BEC12BE2262D39BCF14D", 16);

               BigInteger d = new BigInteger("183f60fdf7951ff47d67193f8d073790c1c9b5a3e", 16);
               ECPoint Q = P.Multiply(d).Negate();

               ECDomainParameters domain = new ECDomainParameters(curve, P, n);
               ICipherParameters privKey = new ParametersWithRandom(new ECPrivateKeyParameters(d, domain), random);
               ECPublicKeyParameters pubKey = new ECPublicKeyParameters(Q, domain);

               Dstu4145Signer dstuSigner = new Dstu4145Signer();
               dstuSigner.Init(true, privKey);
               BigInteger[] rs = dstuSigner.GenerateSignature(hash);

               if (rs[0].CompareTo(r) != 0)
               {
                    return new SimpleTestResult(false, Name + " test 163: expected r: " + r.ToString(16) + " got r:" + rs[0].ToString(16));
               }

               if (rs[1].CompareTo(s) != 0)
               {
                    return new SimpleTestResult(false, Name + " test 163: expected s: " + s.ToString(16) + " got s:" + rs[1].ToString(16));
               }

               dstuSigner.Init(false, pubKey);
               if (!dstuSigner.VerifySignature(hash, r, s))
               {
                    return new SimpleTestResult(false, Name + " test 163: verification failed");
               }

               return new SimpleTestResult(true, Name + ": Okay");
          }
     }
}
