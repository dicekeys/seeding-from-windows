using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DiceKeysWindowsCommandLine
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] seed = new byte[32];
            for (byte i = 0; i < seed.Length; i++) { seed[i] = i; }
            HID.findSoloKeyDevicePaths(seed);
            Console.ReadLine();

        }
    }
}
