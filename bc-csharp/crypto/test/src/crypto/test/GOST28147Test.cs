using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
	[TestFixture]
	public class Gost28147Test
		: CipherTest
	{
		static string input1 =  "0000000000000000";
		static string output1 = "1b0bbc32cebcab42";
		static string input2 =  "bc350e71aac5f5c2";
		static string output2 = "d35ab653493b49f5";
		static string input3 =  "bc350e71aa11345709acde";
		static string output3 = "8824c124c4fd14301fb1e8";
		static string input4 =  "000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f";
		static string output4 = "29b7083e0a6d955ca0ec5b04fdb4ea41949f1dd2efdf17baffc1780b031f3934";

		static byte[] TestSBox = {
				0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF,
				0xF,0xE,0xD,0xC,0xB,0xA,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0,
				0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF,
				0xF,0xE,0xD,0xC,0xB,0xA,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0,
				0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF,
				0xF,0xE,0xD,0xC,0xB,0xA,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0,
				0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF,
				0xF,0xE,0xD,0xC,0xB,0xA,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0
		};

		static SimpleTest[] tests =
		{   new BlockCipherVectorTest(1, new Gost28147Engine(),
				new KeyParameter(Hex.Decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")),
					input1, output1),
			new BlockCipherVectorTest(2, new CbcBlockCipher(new Gost28147Engine()),
				new ParametersWithIV(new KeyParameter(Hex.Decode("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")),
				Hex.Decode("1234567890abcdef")), input2, output2),
			new BlockCipherVectorTest(3, new GOfbBlockCipher(new Gost28147Engine()),
				new ParametersWithIV(new KeyParameter(Hex.Decode("0011223344556677889900112233445566778899001122334455667788990011")),
				Hex.Decode("1234567890abcdef")), //IV
				input3, output3),
			new BlockCipherVectorTest(4, new CfbBlockCipher(new Gost28147Engine(), 64),
				new ParametersWithIV(new KeyParameter(Hex.Decode("aafd12f659cae63489b479e5076ddec2f06cb58faafd12f659cae63489b479e5")),
				Hex.Decode("aafd12f659cae634")), input4, output4),

			//tests with parameters, set S-box.
			new BlockCipherVectorTest(5, new Gost28147Engine(),
				new KeyParameter(Hex.Decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")),//key , default parameter S-box set to D-Test
				input1, output1),
			new BlockCipherVectorTest(6, new CfbBlockCipher(new Gost28147Engine(), 64),
				new ParametersWithIV(
					new ParametersWithSBox(
						new KeyParameter(Hex.Decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")), //key
						Gost28147Engine.GetSBox("D-Test")), //type S-box
					Hex.Decode("1234567890abcdef")), //IV
					"0000000000000000", //input message
					"b587f7a0814c911d"), //encrypt message
			new BlockCipherVectorTest(7, new CfbBlockCipher(new Gost28147Engine(), 64),
				new ParametersWithIV(
					new ParametersWithSBox(
						new KeyParameter(Hex.Decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")), //key
						Gost28147Engine.GetSBox("E-Test")), //type S-box
					Hex.Decode("1234567890abcdef")), //IV
					"0000000000000000", //input message
					"e8287f53f991d52b"), //encrypt message
			new BlockCipherVectorTest(8, new CfbBlockCipher(new Gost28147Engine(), 64),
				new ParametersWithIV(
					new ParametersWithSBox(
						new KeyParameter(Hex.Decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")), //key
						Gost28147Engine.GetSBox("E-A")), //type S-box
					Hex.Decode("1234567890abcdef")), //IV
					"0000000000000000", //input message
					"c41009dba22ebe35"), //encrypt message
			new BlockCipherVectorTest(9, new CfbBlockCipher(new Gost28147Engine(), 8),
				new ParametersWithIV(
					new ParametersWithSBox(
						new KeyParameter(Hex.Decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")), //key
						Gost28147Engine.GetSBox("E-B")), //type S-box
					Hex.Decode("1234567890abcdef")), //IV
					"0000000000000000", //input message
					"80d8723fcd3aba28"), //encrypt message
			new BlockCipherVectorTest(10, new CfbBlockCipher(new Gost28147Engine(), 8),
				new ParametersWithIV(
					new ParametersWithSBox(
						new KeyParameter(Hex.Decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")), //key
						Gost28147Engine.GetSBox("E-C")), //type S-box
					Hex.Decode("1234567890abcdef")), //IV
					"0000000000000000", //input message
					"739f6f95068499b5"), //encrypt message
			new BlockCipherVectorTest(11, new CfbBlockCipher(new Gost28147Engine(), 8),
				new ParametersWithIV(
					new ParametersWithSBox(
						new KeyParameter(Hex.Decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")), //key
						Gost28147Engine.GetSBox("E-D")), //type S-box
					Hex.Decode("1234567890abcdef")), //IV
					"0000000000000000", //input message
					"4663f720f4340f57"), //encrypt message
			new BlockCipherVectorTest(12, new CfbBlockCipher(new Gost28147Engine(), 8),
				new ParametersWithIV(
					new ParametersWithSBox(
						new KeyParameter(Hex.Decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")), //key
						Gost28147Engine.GetSBox("D-A")), //type S-box
					Hex.Decode("1234567890abcdef")), //IV
					"0000000000000000", //input message
					"5bb0a31d218ed564"), //encrypt message
			new BlockCipherVectorTest(13, new CfbBlockCipher(new Gost28147Engine(), 8),
				new ParametersWithIV(
					new ParametersWithSBox(
						new KeyParameter(Hex.Decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")), //key
						TestSBox), //set own S-box
					Hex.Decode("1234567890abcdef")), //IV
					"0000000000000000", //input message
					"c3af96ef788667c5"), //encrypt message
			new BlockCipherVectorTest(14, new GOfbBlockCipher(new Gost28147Engine()),
				new ParametersWithIV(
					new ParametersWithSBox(
							new KeyParameter(Hex.Decode("4ef72b778f0b0bebeef4f077551cb74a927b470ad7d7f2513454569a247e989d")), //key
							Gost28147Engine.GetSBox("E-A")), //type S-box
					Hex.Decode("1234567890abcdef")), //IV
					"bc350e71aa11345709acde",  //input message
					"1bcc2282707c676fb656dc"), //encrypt message

		};

		private const int Gost28147_KEY_LENGTH = 32;

		private byte[] generateKey(byte[] startkey)
		{
			byte[] newKey = new byte[Gost28147_KEY_LENGTH];

			Gost3411Digest digest = new Gost3411Digest();

			digest.BlockUpdate(startkey, 0, startkey.Length);
			digest.DoFinal(newKey, 0);

			return newKey;
		}

		public Gost28147Test()
			: base(tests, new Gost28147Engine(), new KeyParameter(new byte[32]))
		{
		}

		public override void PerformTest()
		{
			base.PerformTest();

			//advanced tests with Gost28147KeyGenerator:
			//encrypt on hesh message; ECB mode:
			byte[] inBytes = Hex.Decode("4e6f77206973207468652074696d6520666f7220616c6c20");
			byte[] output = Hex.Decode("8ad3c8f56b27ff1fbd46409359bdc796bc350e71aac5f5c0");
			byte[] outBytes = new byte[inBytes.Length];

			byte[] key = generateKey(Hex.Decode("0123456789abcdef"));  //!!! heshing start_key - get 256 bits !!!
	//        System.out.println(new string(Hex.Encode(key)));
			ICipherParameters  param = new ParametersWithSBox(new KeyParameter(key), Gost28147Engine.GetSBox("E-A"));
			//CipherParameters  param = new Gost28147Parameters(key,"D-Test");
			BufferedBlockCipher cipher = new BufferedBlockCipher(new Gost28147Engine());

			cipher.Init(true, param);
			int len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);
			try
			{
				cipher.DoFinal(outBytes, len1);
			}
			catch (CryptoException e)
			{
				Fail("failed - exception " + e.ToString(), e);
			}

			if (outBytes.Length != output.Length)
			{
				Fail("failed - "
					+ "expected " + Hex.ToHexString(output) + " got "
					+ Hex.ToHexString(outBytes));
			}

			for (int i = 0; i != outBytes.Length; i++)
			{
				if (outBytes[i] != output[i])
				{
					Fail("failed - "
						+ "expected " + Hex.ToHexString(output)
						+ " got " + Hex.ToHexString(outBytes));
				}
			}


			//encrypt on hesh message; CFB mode:
			inBytes = Hex.Decode("bc350e71aac5f5c2");
			output = Hex.Decode("0ebbbafcf38f14a5");
			outBytes = new byte[inBytes.Length];

			key = generateKey(Hex.Decode("0123456789abcdef"));  //!!! heshing start_key - get 256 bits !!!
			param = new ParametersWithIV(
				new ParametersWithSBox(
					new KeyParameter(key), //key
					Gost28147Engine.GetSBox("E-A")), //type S-box
				Hex.Decode("1234567890abcdef")); //IV

			cipher = new BufferedBlockCipher(new CfbBlockCipher(new Gost28147Engine(), 64));

			cipher.Init(true, param);
			len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);
			try
			{
				cipher.DoFinal(outBytes, len1);
			}
			catch (CryptoException e)
			{
				Fail("failed - exception " + e.ToString(), e);
			}
			if (outBytes.Length != output.Length)
			{
				Fail("failed - "
					+ "expected " + Hex.ToHexString(output)
					+ " got " + Hex.ToHexString(outBytes));
			}
			for (int i = 0; i != outBytes.Length; i++)
			{
				if (outBytes[i] != output[i])
				{
					Fail("failed - "
						+ "expected " + Hex.ToHexString(output)
						+ " got " + Hex.ToHexString(outBytes));
				}
			}


			//encrypt on hesh message; CFB mode:
			inBytes = Hex.Decode("000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f");
			output = Hex.Decode("64988982819f0a1655e226e19ecad79d10cc73bac95c5d7da034786c12294225");
			outBytes = new byte[inBytes.Length];

			key = generateKey(Hex.Decode("aafd12f659cae63489b479e5076ddec2f06cb58faafd12f659cae63489b479e5"));  //!!! heshing start_key - get 256 bits !!!
			param = new ParametersWithIV(
				new ParametersWithSBox(
					new KeyParameter(key), //key
					Gost28147Engine.GetSBox("E-A")), //type S-box
				Hex.Decode("aafd12f659cae634")); //IV

			cipher = new BufferedBlockCipher(new CfbBlockCipher(new Gost28147Engine(), 64));

			cipher.Init(true, param);
			len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

			cipher.DoFinal(outBytes, len1);

			if (outBytes.Length != output.Length)
			{
				Fail("failed - "
					+ "expected " + Hex.ToHexString(output)
					+ " got " + Hex.ToHexString(outBytes));
			}

			for (int i = 0; i != outBytes.Length; i++)
			{
				if (outBytes[i] != output[i])
				{
					Fail("failed - "
						+ "expected " + Hex.ToHexString(output)
						+ " got " + Hex.ToHexString(outBytes));
				}
			}

			//encrypt on hesh message; OFB mode:
			inBytes = Hex.Decode("bc350e71aa11345709acde");
			output = Hex.Decode("1bcc2282707c676fb656dc");
			outBytes = new byte[inBytes.Length];

			key = generateKey(Hex.Decode("0123456789abcdef"));  //!!! heshing start_key - get 256 bits !!!
			param = new ParametersWithIV(
				new ParametersWithSBox(
					new KeyParameter(key), //key
					Gost28147Engine.GetSBox("E-A")), //type S-box
				Hex.Decode("1234567890abcdef")); //IV

			cipher = new BufferedBlockCipher(new GOfbBlockCipher(new Gost28147Engine()));

			cipher.Init(true, param);
			len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

			cipher.DoFinal(outBytes, len1);

			if (outBytes.Length != output.Length)
			{
				Fail("failed - "
					+ "expected " + Hex.ToHexString(output)
					+ " got " + Hex.ToHexString(outBytes));
			}

			for (int i = 0; i != outBytes.Length; i++)
			{
				if (outBytes[i] != output[i])
				{
					Fail("failed - "
						+ "expected " + Hex.ToHexString(output)
						+ " got " + Hex.ToHexString(outBytes));
				}
			}


               AdditionalGofbTests();

		}

          private void AdditionalGofbTests()
          {
               byte[] sBox = 
               {
                    0xE, 0x3, 0xC, 0xD, 0x1, 0xF, 0xA, 0x9, 0xB, 0x6, 0x2, 0x7, 0x5, 0x0, 0x8, 0x4,
                    0xD, 0x9, 0x0, 0x4, 0x7, 0x1, 0x3, 0xB, 0x6, 0xC, 0x2, 0xA, 0xF, 0xE, 0x5, 0x8,
                    0x8, 0xB, 0xA, 0x7, 0x1, 0xD, 0x5, 0xC, 0x6, 0x3, 0x9, 0x0, 0xF, 0xE, 0x2, 0x4,
                    0xD, 0x7, 0xC, 0x9, 0xF, 0x0, 0x5, 0x8, 0xA, 0x2, 0xB, 0x6, 0x4, 0x3, 0x1, 0xE,
                    0xB, 0x4, 0x6, 0x5, 0x0, 0xF, 0x1, 0xC, 0x9, 0xE, 0xD, 0x8, 0x3, 0x7, 0xA, 0x2,
                    0xD, 0xF, 0x9, 0x4, 0x2, 0xC, 0x5, 0xA, 0x6, 0x0, 0x3, 0x8, 0x7, 0xE, 0x1, 0xB,
                    0xF, 0xE, 0x9, 0x5, 0xB, 0x2, 0x1, 0x8, 0x6, 0x0, 0xD, 0x3, 0x4, 0x7, 0xC, 0xA,
                    0xA, 0x3, 0xE, 0x2, 0x0, 0x1, 0x4, 0x6, 0xB, 0x8, 0xC, 0x7, 0xD, 0x5, 0xF, 0x9
               };

               byte[] inBytes = new byte[16];
               byte[] output = new byte[16];
               byte[] outBytes = new byte[16];
               ICipherParameters param;
               
               int len1 = 0;
               byte[] key = Hex.Decode("0A43145BA8B9E9FF0AEA67D3F26AD87854CED8D9017B3D33ED81301F90FDF993");
               BufferedBlockCipher cipher = new BufferedBlockCipher(new GOfbBlockCipher(new Gost28147Engine()));


               //Test 0
               inBytes = Hex.Decode("DC5341C357558251");
               output = Hex.Decode("0001261c637fde88");
               
               outBytes = new byte[inBytes.Length];

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8006FEE08006FEE0")); //IV

               cipher = new BufferedBlockCipher(new GOfbBlockCipher(new Gost28147Engine()));

               cipher.Init(false, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("TEST 0 failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("TEST 0 failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 1
               inBytes = Hex.Decode("094C912C5EFDD703D42118971694580B");
               output = Hex.Decode("2707B58DF039D1A64460735FFE76D55F");
               //Previous error result: BF0A469944BD9D38D1978A4C17B173CD

               outBytes = new byte[inBytes.Length];

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001069080010690")); //IV

               cipher = new BufferedBlockCipher(new GOfbBlockCipher(new Gost28147Engine()));

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }


               //Test 2
               inBytes = Hex.Decode("FE780800E0690083F20C010CF00C0329");
               output = Hex.Decode("9AF623DFF948B413B53171E8D546188D");
               //Previous error result: 9EAD5C8208FA6C212502D18E273A0FE6

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("800107A0800107A0")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 3
               inBytes = Hex.Decode("D1088FD8C0A86EE8F1DCD1088FE8C058");
               output = Hex.Decode("62A6B64D12253BCD8241A4BB0CFD3E7C");
               //Previous error result: 109D59C74656E8C5C09A55541E54B353

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001114080011140")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 4
               inBytes = Hex.Decode("D431FACD011C502C501B500A12921090");
               output = Hex.Decode("07313C89D302FF73234B4A0506AB00F3");
               //Previous error result: E97D320CD1D1C78185318A198108A4DA

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("80011A3080011A30")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 5
               inBytes = Hex.Decode("201A143BC1E5C2684999928810023018");
               output = Hex.Decode("AC226E25EC626DF74074322440B473B4");
               //Previous error result: 18214CCF8A4FAA47D5EC4C10680D493A

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("80011C9080011C90")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }


               //Test 6
               inBytes = Hex.Decode("FAC9FFFF1698301A320E1186138CF806");
               output = Hex.Decode("C9BEBEAF8B953304B1EF6C2063917D81");
               //Previous error result: BBD17E87E6BAE485CE0BF0DADEE150EE

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("80011E1080011E10")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }


               //Test 7
               inBytes = Hex.Decode("580CF9BC0101F9B80001EFF80A89F9BC");
               output = Hex.Decode("352CD20D54364A79857E94661026A599");

               //Previous error result: B618FE51A75EEF645FC38B47B9F4ACEC

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("800126E0800126E0")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }


               //Test 8
               inBytes = Hex.Decode("F01F0053584CC1F1F01F00524D287029");
               output = Hex.Decode("E44CA05846C9F7F79117A70D798E6897");

               //Previous error result: E44CA05846C9F7F73552A35860F131C8

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001275080012750")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 9
               inBytes = Hex.Decode("B888B898B8A8B8B8B8C8B8D85809C0C0");
               output = Hex.Decode("3568BB137C9D5EB9820470216BC5BCAD");

               //Previous error result: 3568BB137C9D5EB910CB835EEE01567F

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("80012A1080012A10")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 10
               inBytes = Hex.Decode("338133903086C2E83588EE0C0A18F8C9");
               output = Hex.Decode("96E22E29187D42F63D6677BC9F38C551");

               //Previous error result: 171A3AA78F47C0A4601C5A9AC6DCC79C

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001325080013250")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 11
               inBytes = Hex.Decode("E609032AF4CAF060E609092AEC091505");
               output = Hex.Decode("9D605780ED22E439DF4CDE014930F1A2");

               //Previous error result: 4F3A27DA3BF0BDA6FFBBC238B0D602D8

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("80014DB080014DB0")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 12
               inBytes = Hex.Decode("800162D4000059E400005A84800166B4");
               output = Hex.Decode("AF46334A140948A6D29ADE736402A2ED");

               //Previous error result: AF46334A140948A6AA7D9A67186CB2AD

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("80014FF080014FF0")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 13
               inBytes = Hex.Decode("00399018B218F01F004AA9630605AA6C");
               output = Hex.Decode("E810EF82F1689A74DFE60C3773E425E3");

               //Previous error result: E810EF82F1689A74A865EEE68C1817A4

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("800151E0800151E0")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 14
               inBytes = Hex.Decode("0005AA6CE6040338F0091508EE090009");
               output = Hex.Decode("37123BC9FBE60AE86A2A9F4693090304");

               //Previous error result: 2D748F22BB813903BBDB89BE83970A38

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("80015E6080015E60")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 15
               inBytes = Hex.Decode("CA98E0695A5AEA19ABCD123CE08000B6");
               output = Hex.Decode("EC8EB64592F0616B2EEC6ACDBE3BC8FB");

               //Previous error result: EC8EB64592F0616BEA3B8561F78937AE

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("80015F8080015F80")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 16
               inBytes = Hex.Decode("F80A15022FFAFEF913FEF20A033AF40B");
               output = Hex.Decode("757ABEA8F49D1F0755A4BF126D280C04");

               //Previous error result: 757ABEA8F49D1F0712131633AC99E782

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001699080016990")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 17
               inBytes = Hex.Decode("0014301AF4081900E08100C1F3390016");
               output = Hex.Decode("8793B6D6E1143B1A686BFF6C9C83A742");

               //Previous error result: 8793B6D6E1143B1A44FA69EFF1F1ACE0

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("80016EA080016EA0")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 18
               inBytes = Hex.Decode("F01F019FFEF80660F0F802285808E081");
               output = Hex.Decode("EFD33CDEF76DE309E24C6A82A77878C8");

               //Previous error result: 39E6DC5FA02E1AD836425CE4C5B8BEBB

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001775080017750")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 19
               inBytes = Hex.Decode("4EF87018F1090014AC29F1080012AC18");
               output = Hex.Decode("699CB93FA59B0B797F34E802CC4B7DBD");

               //Previous error result: 699CB93FA59B0B79FB0BEE465DD9646B

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("800182A0800182A0")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 20
               inBytes = Hex.Decode("09EAFEFC09EAF00B00090D8AF00A003A");
               output = Hex.Decode("CF05DC4A92BE35386EED2E6D1029BE57");

               //Previous error result: 2454652A8BA3423B4D0330DC6F1325E3

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001855080018550")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 21
               inBytes = Hex.Decode("F30A00104E78B00AF30A0012B01AF30A");
               output = Hex.Decode("802C4612AE273128079B40E8A4071431");

               //Previous error result: A66AAD31C129F57232D25E6C404D2CB5

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("80018DF080018DF0")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 22
               inBytes = Hex.Decode("EA03000B0E9CF01F004018566E08EC08");
               output = Hex.Decode("84CEB3BEB8FBC42A7492C862B01D96BF");

               //Previous error result: BE71190EFCAAA85003FC6260D8FE1D49

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001926080019260")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 23
               inBytes = Hex.Decode("E048002AC0303009C7980F88F0C90030");
               output = Hex.Decode("AA51804F880C3AE3BB0545C9E5385787");

               //Previous error result: AA51804F880C3AE3CE18E450406E63A4

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001AB808001AB80")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 24
               inBytes = Hex.Decode("F940FAC9FFB4FEB0FB012FDD780BC248");
               output = Hex.Decode("9E993DABFA62C356003AFDB09AABB0D7");

               //Previous error result: 9E993DABFA62C356A3ADF3369C622F58

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001AF608001AF60")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 25
               inBytes = Hex.Decode("0047F00617A03032E08F06C2402A5BFA");
               output = Hex.Decode("87FA20B2B5ABBD5924CC55C2DA5EA9D3");

               //Previous error result: 87FA20B2B5ABBD59149A67CFE567249D

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001B1708001B170")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 26
               inBytes = Hex.Decode("FAC9F9441497F2060036ECEAFD88FAEB");
               output = Hex.Decode("E8E5EA02F1B0107ED0C77E3747C8FD32");

               //Previous error result: D6E0B8F56464D426E93EE3367D712419

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001B6208001B620")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 27
               inBytes = Hex.Decode("C161FAF806B4403E580EC0801036C674");
               output = Hex.Decode("70A15ABD3D31DA9311855F2F1FE73206");

               //Previous error result: F01772C87D269F5F2FFC16ADD72BD1C2

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001B6808001B680")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 28
               inBytes = Hex.Decode("F9447209EC08003AF549FD882FF8FB48");
               output = Hex.Decode("2A153E4689961B7E79435E2B512C0A9F");

               //Previous error result: 2A153E4689961B7E5CE052962044BB6F

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001B8508001B850")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 29
               inBytes = Hex.Decode("FBB41AD8FAC8F940FAC9FFB4049A0C9B");
               output = Hex.Decode("2AF4471A83EE0AECAECA26899AC916E5");

               //Previous error result: 2AF4471A83EE0AECD5F3B406E0DEAE82

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001BA908001BA90")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 30
               inBytes = Hex.Decode("C0701095FB6006B93308FB6806B83028");
               output = Hex.Decode("ECC916FD6093A00C35086DB8782BCDAF");

               //Previous error result: ECC916FD6093A00C7D08F4C97C48515E

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001BDC08001BDC0")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 31
               inBytes = Hex.Decode("0008C0B0FAF8069087128706F0020002");
               output = Hex.Decode("1154A1ED86B67BEC3FA658AA1F54F7AB");

               //Previous error result: C2EE28005F111786C89FCE6F459FF1B5

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001C1708001C170")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 32
               inBytes = Hex.Decode("0690FEC9A3B22FF88709FB4806903019");
               output = Hex.Decode("DC191D340C8DD1B8F85B6B87E084460A");

               //Previous error result: 5B27713AA280F324BF855C347CACCFC0

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001C1A08001C1A0")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 33
               inBytes = Hex.Decode("000851596E955805C091310CFEB0E636");
               output = Hex.Decode("98408B9F198A465E03ECE491C8FDE3C0");

               //Previous error result: 98408B9F198A465E70308A3865769C3C

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001C9F08001C9F0")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 34
               inBytes = Hex.Decode("000841682D080AC841392FF95139FAE8");
               output = Hex.Decode("ECE5D1D25E3D47020446A4BB9A53798E");

               //Previous error result: 7A4EB3800A2698391672B16D7481258F

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001CF008001CF00")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 35
               inBytes = Hex.Decode("8F28C2E808365FBA6E0C6E48103C5FB8");
               output = Hex.Decode("DE76FC190F15C59041933B5E2854A225");

               //Previous error result: A7E4BD46B9171AADE2CA3E57A68BE821

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001DB808001DB80")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 36
               inBytes = Hex.Decode("F9BC0100109AF0091508E61AFF00F7BC");
               output = Hex.Decode("819DBA174B7D311A38D6B79297E239AB");

               //Previous error result: DCC128FC014F61672A93B4BC3D31653A

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001DE408001DE40")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 37
               inBytes = Hex.Decode("000F144BE08100A7F2061614ABD6E046");
               output = Hex.Decode("9E49B804D9CB09C8D09BC1F568E59F55");

               //Previous error result: 3A71A4AEFFCE2F2B050AC9AE86F3E8B1

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001F1708001F170")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 38
               inBytes = Hex.Decode("0000000048353651434E39504133414E");
               output = Hex.Decode("926F66985AB121E6678F91D5C574478F");

               //Previous error result: 926F66985AB121E6066C79670ED1CDCA

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8001FC708001FC70")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 39
               inBytes = Hex.Decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
               output = Hex.Decode("24E245C4DCF36B77EF149ED118B5F58E");

               //Previous error result: 056A6502D0D3106F1842079DF4957A05

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8002008080020080")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 40
               inBytes = Hex.Decode("010D050C060309000F0E02040D090004");
               output = Hex.Decode("91504CA18ABA4D206C76E486B3CC54BD");

               //Previous error result: 91504CA18ABA4D2083CB19EA059F2105

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("800204A0800204A0")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 41
               inBytes = Hex.Decode("00300030006D001B005B003000310053");
               output = Hex.Decode("425A07AEB46DBDB8877FA0EB7E299031");

               //Previous error result: 425A07AEB46DBDB8C9D3012EBF45476B

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8002083080020830")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 42
               inBytes = Hex.Decode("00000000000000000000000000000000");
               output = Hex.Decode("225DE0B9D01100CF86068350D180FBA8");

               //Previous error result: 225DE0B9D01100CFEACF3C2B07055B95

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("80020A8080020A80")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 43
               inBytes = Hex.Decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
               output = Hex.Decode("BCB6F7DE40336D9662E66F9953871BC9");

               //Previous error result: 4CEA926986F571C0850514621529AC87

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("80020CB080020CB0")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 44
               inBytes = Hex.Decode("003D003D003D003D003D003D003D003D");
               output = Hex.Decode("85C5D740DFD784DF0E7BCDC14AF810C0");

               //Previous error result: 85C5D740DFD784DF77503FD24F13EBE3

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("800210A0800210A0")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 45
               inBytes = Hex.Decode("04560020002000200020002000200020");
               output = Hex.Decode("5E3495F6A9858061FD847B5D8B12ED58");

               //Previous error result: 8291FE82C85E27385438878A681FA083

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("800214F0800214F0")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }

               //Test 46
               inBytes = Hex.Decode("043A043B044E044704560432003F0020");
               output = Hex.Decode("68C9D595994E25DA052788F2D17ECEA7");

               //Previous error result: 68C9D595994E25DA1AA74A22AAD50646

               param = new ParametersWithIV(
                    new ParametersWithSBox(
                         new KeyParameter(key), //key
                        sBox), //type S-box
                    Hex.Decode("8002197080021970")); //IV

               cipher.Init(true, param);
               len1 = cipher.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);

               if (outBytes.Length != output.Length)
               {
                    Fail("failed - "
                         + "expected " + Hex.ToHexString(output)
                         + " got " + Hex.ToHexString(outBytes).ToUpper());
               }

               for (int i = 0; i != outBytes.Length; i++)
               {
                    if (outBytes[i] != output[i])
                    {
                         Fail("failed - "
                              + "expected " + Hex.ToHexString(output)
                              + " got " + Hex.ToHexString(outBytes).ToUpper());
                    }
               }
                             
          }

		public override string Name
		{
			get { return "Gost28147"; }
		}

		public static void Main(
			string[] args)
		{
			ITest test = new Gost28147Test();
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
