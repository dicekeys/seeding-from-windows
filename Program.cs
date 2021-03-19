using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DiceKeysWindowsCommandLine
{
    class Program
    {

        public static bool IsHexChar(char c)
        {
            return (c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F');
        }

        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
            {
                // Ensure this is valid hex and abort otherwise
                if (!IsHexChar(hex[i]) || !IsHexChar(hex[i + 1])) return null;
                // Convert hex
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        /// <summary>
        /// Parse an argument to see if it is a 32-byte seed in hex format (64-characters),
        /// optionally prefixed with "0x"
        /// </summary>
        /// <param name="arg"></param>
        /// <returns>A 32-byte string if a valid hex seed was read, or null otherwise.</returns>
        static byte[] Parse32ByteSeedFromHexFormat(string arg)
        {
            if (arg.Length == 66 && arg.StartsWith("0x"))
            {
                arg = arg.Substring(2);
            }
            return StringToByteArray(arg);
        }

        static void Main(string[] args)
        {
            byte[] seed = null;

//            for (byte i = 0; i < seed.Length; i++) { seed[i] = i; }

            for (int argIndex=0; argIndex < args.Length; argIndex++)
            {
                string arg = args[argIndex].Trim();
                byte[] possibleSeed = Parse32ByteSeedFromHexFormat(arg);
                if (possibleSeed != null)
                    seed = possibleSeed;
            }

            if (seed == null)
            {
                Console.WriteLine("No seed provided");
                return;
            }

            Console.WriteLine($"Seed set to {BitConverter.ToString(seed).Replace("-", "")}");
            HID.findSoloKeyDevicePaths(seed);
            // Console.ReadLine();
        }
    }
}
