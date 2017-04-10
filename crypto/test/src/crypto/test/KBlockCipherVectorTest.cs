using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    /**
	* a basic test that takes a cipher, key parameter, and an input
	* and output string. This test wraps the engine in a buffered block
	* cipher with padding disabled.
	*/
    public class KBlockCipherVectorTest : SimpleTest
    {        
		int                 id;
		IBlockCipher         engine;
		ICipherParameters    param;
		byte[]              input;
		byte[]              output;

		public KBlockCipherVectorTest(
			int					id,
			IBlockCipher		engine,
			ICipherParameters	param,
			string				input,
			string				output)
		{
			this.id = id;
			this.engine = engine;
			this.param = param;
			this.input = Hex.Decode(input);
			this.output = Hex.Decode(output);
		}

		public override string Name
		{
			get
			{
				return engine.AlgorithmName + " Vector Test " + id;
			}
		}

		public override void PerformTest()
		{
               //KBufferedBlockCipher does slightly different partial block processing
			KBufferedBlockCipher cipher = new KBufferedBlockCipher(engine);

               cipher.Init(true, param);

			byte[] outBytes = new byte[input.Length];
               
			int len1 = cipher.ProcessBytes(input, 0, input.Length, outBytes, 0);

               cipher.DoFinal(outBytes, len1);
               
			if (!AreEqual(outBytes, output))
			{
				Fail("failed." + "\nExpected " + Hex.ToHexString(output) + "\nGot      " + Hex.ToHexString(outBytes));
			}

			cipher.Init(false, param);

			int len2 = cipher.ProcessBytes(output, 0, output.Length, outBytes, 0);

			cipher.DoFinal(outBytes, len2);

			if (!AreEqual(input, outBytes))
			{
				Fail("failed reversal got " + Hex.ToHexString(outBytes));
			}
		}
	}
}
