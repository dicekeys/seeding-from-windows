using System;
using System.Threading;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.IO;
using System.Linq;
// using DiceKeysWindowsCommandLine.WinHID;
//using System.Globalization;

namespace DiceKeysWindowsCommandLine
{

    class HidInitPacket
    {
        public readonly uint channel;
        public readonly byte command;
        public readonly ushort length;
        public readonly byte[] data;

        public HidInitPacket(byte[] packet)
        {
            using (MemoryStream ms = new MemoryStream(packet))
            {
                using (BinaryReader br = new BinaryReader(ms))
                {
                    channel = br.ReadUInt32();
                    command = (byte) (br.ReadByte() & 0x7f);
                    length = (ushort)(((ushort)br.ReadByte()) << 8);
                    length |= (ushort)br.ReadByte();
                    data = br.ReadBytes(Math.Min((int)length, 64 - 7));
                }
            }
        }
    }

    public partial class HID {
        const byte COMMAND_GET_CHANNEL = 0x06;
        const byte COMMAND_ERROR = 0x3F;
        const byte COMMAND_WRITE_SEED = 0x62;

        /*
         *            INITIALIZATION PACKET
         *            Offset   Length    Mnemonic    Description
         *            0        4         CID         Channel identifier
         *            4        1         CMD         Command identifier (bit 7 always set)
         *            5        1         BCNTH       High part of payload length
         *            6        1         BCNTL       Low part of payload length
         *            7        (s - 7)   DATA        Payload data (s is equal to the fixed packet size)
         */

        static byte[] createInitPacket(uint channel, byte command, byte[] data)
        {
            //            byte[] binaryData;
            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    bw.Write(channel);
                    byte commandByte = (byte)(0x80 | command);
                    bw.Write(commandByte);
                    byte lengthHiByte = (byte) (data.Length >> 8);
                    byte lengthLoByte = (byte) (data.Length & 0xff);
                    bw.Write(lengthHiByte);
                    bw.Write(lengthLoByte);
                    bw.Write(data, 0, Math.Min(data.Length, 64 - 7));
                    bw.Flush();
                    byte[] filledBytes = ms.GetBuffer().Take(64).ToArray();
                    return filledBytes.Concat(new byte[64 - filledBytes.Length]).ToArray();
                }
            }
        }

        static byte[] readReport(IntPtr hidDeviceFileHandle)
        {
            Byte[] reportRead = new byte[65];
            UInt32 tmp = 0;
            ReadFile(hidDeviceFileHandle, reportRead, (uint) reportRead.Length, ref tmp, IntPtr.Zero);
            byte reportType = reportRead[0];
            return reportRead.Skip(1).ToArray();
        }

        static uint getChannel(IntPtr hidDeviceFileHandle)
        {
            byte[] nonce = new byte[8];
            new Random().NextBytes(nonce);
            // System.Security.Cryptography.GetBytes(nonce);
            byte[] getChannelRequestPacket = createInitPacket(0xffffffff, COMMAND_GET_CHANNEL, nonce);
            writeReport(hidDeviceFileHandle, getChannelRequestPacket);
            while(true)
            {
                HidInitPacket packet = new HidInitPacket(readReport(hidDeviceFileHandle));
                var nonceRead = packet.data.Take(8).ToArray();
                if (nonceRead.SequenceEqual(nonce))
                {
                    return BitConverter.ToUInt32(packet.data, 8);
                }
            }
        }

        static Boolean seedSoloKey(IntPtr hidDeviceFileHandle, byte[] seed)
        {
            uint channel = getChannel(hidDeviceFileHandle);
            // SoloKeys code triggered by this call is at:
            // https://github.com/conorpp/solo/blob/eae4af7dcd2aef689b16a43adf0e1719adcc9f16/fido2/ctaphid.c#L786
            // bytes:       1        32     0..256
            // payload:  version  seedKey  extState
            if (seed.Length != 32)
            {
                // FIXME -- throw error
                return false;
            }
            byte[] version = new byte[1];
            version[0] = 1;
            byte[] data = version.Concat(seed).ToArray();
            byte[] writeSeedPacket = createInitPacket(channel, COMMAND_WRITE_SEED, data);
            writeReport(hidDeviceFileHandle, writeSeedPacket);
            while (true)
            {
                HidInitPacket packet = new HidInitPacket(readReport(hidDeviceFileHandle));
                if (packet.channel == channel)
                {
                    Console.WriteLine($"SoloKey responds: {packet.command == COMMAND_WRITE_SEED}");
                    return packet.command == COMMAND_WRITE_SEED;
                }
            }
        }


        static void writeReport(IntPtr hidDeviceFileHandle, Byte[] packet)
        {
            if (packet.Length != 64)
            {
                // FIXME throw
            }
            Byte[] buffer = new Byte[65];
            buffer[0] = 0; // always use report id of 0
            packet.CopyTo(buffer, 1);
            UInt32 tmp = 0;
            WriteFile(hidDeviceFileHandle, buffer, 65, ref tmp, IntPtr.Zero);
        }

        public static List<string> findSoloKeyDevicePaths(byte[] seed)
        {
            List<string> solokeyDevicePathsFound = new List<string>();
            Guid hidGuid = new Guid();
            HidD_GetHidGuid(ref hidGuid);

            SP_DEVICE_INTERFACE_DATA deviceInfoData = new SP_DEVICE_INTERFACE_DATA();

            SP_DEVICE_INTERFACE_DETAIL_DATA functionClassDeviceData = new SP_DEVICE_INTERFACE_DETAIL_DATA();


            //
            // Open a handle to the plug and play dev node.
            //
            IntPtr hardwareDeviceInfo = SetupDiGetClassDevs(ref hidGuid, IntPtr.Zero, IntPtr.Zero, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
            deviceInfoData.cbSize = Marshal.SizeOf(typeof(SP_DEVICE_INTERFACE_DATA));

            int iHIDD = 0;
            while (SetupDiEnumDeviceInterfaces(hardwareDeviceInfo, IntPtr.Zero, ref hidGuid, iHIDD++, ref deviceInfoData))
            {
                int RequiredLength = 0;

                //
                // allocate a function class device data structure to receive the
                // goods about this particular device.
                //
                SetupDiGetDeviceInterfaceDetail(hardwareDeviceInfo, ref deviceInfoData, IntPtr.Zero, 0, ref RequiredLength, IntPtr.Zero);

                if (IntPtr.Size == 8)
                    functionClassDeviceData.cbSize = 8;
                else if (IntPtr.Size == 4)
                    functionClassDeviceData.cbSize = 5;

                //
                // Retrieve the information from Plug and Play.
                //
                SetupDiGetDeviceInterfaceDetail(hardwareDeviceInfo, ref deviceInfoData, ref functionClassDeviceData, RequiredLength, ref RequiredLength, IntPtr.Zero);

                //
                // Open device with just generic query abilities to begin with
                //
                HIDP_CAPS hidCaps = new HIDP_CAPS();
                HIDD_ATTRIBUTES hidAttributes = new HIDD_ATTRIBUTES();

                IntPtr hidDeviceFileHandle = CreateFile(functionClassDeviceData.DevicePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, IntPtr.Zero);
                IntPtr preparsedDataPointer = IntPtr.Zero;
                HidD_GetPreparsedData(hidDeviceFileHandle, ref preparsedDataPointer);
                HidD_GetAttributes(hidDeviceFileHandle, ref hidAttributes);
                HidP_GetCaps(preparsedDataPointer, ref hidCaps);
                HidD_FreePreparsedData(ref preparsedDataPointer);

                Console.WriteLine($"Found -> Usage Page: {hidCaps.UsagePage:X}, Usage: {hidCaps.Usage:X} ProductID: {hidAttributes.ProductID:X} VendorID: {hidAttributes.VendorID:X}");

                if (hidCaps.UsagePage == 0xF1D0 && hidCaps.Usage == 0x0001 && hidAttributes.ProductID == 0xA2CA && hidAttributes.VendorID == 0x0483)
                {
                    solokeyDevicePathsFound.Add(functionClassDeviceData.DevicePath);
                    Console.WriteLine($"SoloKey path: {functionClassDeviceData.DevicePath}, Buffer Length: {hidCaps.OutputReportByteLength}");
                    seedSoloKey(hidDeviceFileHandle, seed);
                }

                CloseHandle(hidDeviceFileHandle);

            }

            SetupDiDestroyDeviceInfoList(hardwareDeviceInfo);
            return solokeyDevicePathsFound;
        }


        public HID()
        {
        }
    }
}