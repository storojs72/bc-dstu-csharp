using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
	[TestFixture]
	public class Gost3411DigestTest
		: DigestTest
	{
		private static readonly string[] messages =
		{
			"",
			"This is message, length=32 bytes",
			"Suppose the original message has length = 50 bytes",
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		};

		//  If S-box = D-A (see: digest/Gost3411Digest.java; function: E(byte[] in, byte[] key); string: CipherParameters  param = new Gost28147Parameters(key,"D-A");)
		private static readonly string[] digests =
		{
			"981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0",
			"2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb",
			"c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011",
			"73b70a39497de53a6e08c67b6d4db853540f03e9389299d9b0156ef7e85d0f61"
		};

		
		// 1 million 'a'
		static private string million_a_digest = "";




		public Gost3411DigestTest()
			: base(new Gost3411Digest(), messages, digests)
		{
		}

		public override void PerformTest()
		{
			base.PerformTest();

			millionATest(million_a_digest);

            byte[] data = Strings.ToUtf8ByteArray("fred");

            KeyParameter key = new KeyParameter(Pkcs5S1ParametersGenerator.Pkcs5PasswordToUtf8Bytes("1".ToCharArray()));
            byte[] mac = MacUtilities.CalculateMac("HMAC/GOST3411", key, data);

            if (!Arrays.AreEqual(Hex.Decode("e9f98610cfc80084462b175a15d2b4ec10b2ab892eae5a6179d572d9b1db6b72"), mac))
            {
                Fail("mac calculation failed.");
            }
        }

        protected override IDigest CloneDigest(IDigest digest)
		{
			return new Gost3411Digest((Gost3411Digest)digest);
		}

		public static void Main(
			string[] args)
		{
			ITest test = new Gost3411DigestTest();
			ITestResult result = test.Perform();

			Console.WriteLine(result);
		}

		[Test]
		public void TestFunction()
		{
			string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
		}
	}
}
