using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using MemoryScanner.Resources;

namespace MemoryScanner
{
    internal class ProgObj
    {
        // REQUIRED CONSTS
        private const int ProcessQueryInformation = 0x0400;

        private const int MemCommit = 0x00001000;
        private const int PageReadwrite = 0x04;
        private const int ProcessWmRead = 0x0010;

        private const string ArgSocket = "socket";
        private const string ArgFile = "file";
        private const string ArgStandardInputOutput = "stdio";

        // REQUIRED METHODS
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern void GetSystemInfo(out SystemInfo lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MemoryBasicInformation lpBuffer, uint dwLength);

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
                MemScan(myargs);
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

        public static void MemScan(CliArgs myargs)
        {
            Socket sender = null;
            System.IO.StreamWriter file = null;

            // Writing output to socket.
            if (myargs.Mode.Equals(ArgSocket))
            {
                try
                {
                    var ipAddress = IPAddress.Parse(myargs.Ipaddr);
                    var remoteIp = new IPEndPoint(ipAddress, myargs.Portnum);

                    sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    sender.Connect(remoteIp);
                    Console.WriteLine(MessageStrings.SearchStartMessageForStandardIO, sender.RemoteEndPoint);
                }
                catch (SocketException se)
                {
                    Console.WriteLine("SocketException : {0}", se);
                }
            }

            // Writing output to file.
            if (myargs.Mode.Equals(ArgFile))
                file = new System.IO.StreamWriter(myargs.Filename);

            // Get all running processes.
            Process[] localAll = Process.GetProcesses();

            // If we're not proc-hopping, just fill the array with the same PID of our target.
            // A bit of a fudge but avoids lots of duplicate code otherwise...
            if (!myargs.ProcHop)
            {
                for (int i = 0; i < localAll.Length; i++)
                    localAll[i] = Process.GetProcessById(myargs.Pid);
            }

            while (true)
            {
                foreach (Process process in localAll)
                {
                    // Getting minimum & maximum address.
                    SystemInfo sysInfo = new SystemInfo();
                    GetSystemInfo(out sysInfo);

                    IntPtr procMinAddress = sysInfo.MinimumApplicationAddress;
                    IntPtr procMaxAddress = sysInfo.MaximumApplicationAddress;

                    // Saving the values as long ints to avoid lot of casts later.
                    long procMinAddressL = (long)procMinAddress;
                    long procMaxAddressL = (long)procMaxAddress;

                    string toSend = "";

                    // Opening the process with desired access level.
                    IntPtr processHandle = OpenProcess(ProcessQueryInformation | ProcessWmRead, false, process.Id);

                    // We don't want to scrape our own process and if we can't get a handle then it's probalby a protected process.
                    // So don't try and scan it otherwise Mnemosyne will stall.
                    if (process.Id == Process.GetCurrentProcess().Id || processHandle == IntPtr.Zero) continue;

                    Console.WriteLine("Working on processID {0} : {1}", process.Id, process.ProcessName);

                    // This will store any information we get from VirtualQueryEx().
                    MemoryBasicInformation memBasicInfo = new MemoryBasicInformation();

                    // Number of bytes read with ReadProcessMemory.
                    int bytesRead = 0;

                    // For some efficiencies, pre-compute prepostfix values.
                    int postfix = myargs.Searchterm.Length + (myargs.Prepostfix * 2);

                    while (procMinAddressL < procMaxAddressL)
                    {
                        // 28 = sizeof(MEMORY_BASIC_INFORMATION)
                        VirtualQueryEx(processHandle, procMinAddress, out memBasicInfo, 28);

                        // If this memory chunk is accessible.
                        if (memBasicInfo.Protect == PageReadwrite && memBasicInfo.State == MemCommit)
                        {
                            byte[] buffer = new byte[memBasicInfo.RegionSize];

                            // Read everything in the buffer above.
                            ReadProcessMemory((int)processHandle, memBasicInfo.BaseAddress, buffer, memBasicInfo.RegionSize, ref bytesRead);

                            string memStringAscii = Encoding.ASCII.GetString(buffer);
                            string memStringUnicode = Encoding.Unicode.GetString(buffer);

                            if (myargs.IsRegex)
                            {
                                Regex rgx = new Regex(myargs.Searchterm, RegexOptions.IgnoreCase);

                                // Does the regex pattern exist in this chunk in ASCII form?
                                if (rgx.IsMatch(memStringAscii))
                                {
                                    int idex = 0;
                                    while (rgx.Match(memStringAscii, idex).Success)
                                    {
                                        idex = rgx.Match(memStringAscii, idex).Index;
                                        try
                                        {
                                            toSend += process.ProcessName + ":" + process.Id + ":0x" + (memBasicInfo.BaseAddress + idex) + ":A:" + memStringAscii.Substring(idex - myargs.Prepostfix, postfix) + "\n";
                                            OutputString(myargs.Mode, toSend, myargs.Delay, sender, file);
                                        }
                                        // If our width is too large then it may exceed a search chunk and be out of bounds.
                                        catch (ArgumentOutOfRangeException)
                                        {
                                            Console.WriteLine(ErrorStrings.OutOfBoundsError);
                                        }

                                        toSend = "";
                                        idex++;
                                    }
                                }

                                // Does the regex pattern exist in this chunk in UNICODE form?
                                if (rgx.IsMatch(memStringUnicode))
                                {
                                    int idex = 0;
                                    while (rgx.Match(memStringUnicode, idex).Success)
                                    {
                                        idex = rgx.Match(memStringUnicode, idex).Index;
                                        try
                                        {
                                            toSend += process.ProcessName + ":" + process.Id + ":0x" + (memBasicInfo.BaseAddress + idex) + ":U:" + memStringUnicode.Substring(idex - myargs.Prepostfix, postfix) + "\n";
                                            OutputString(myargs.Mode, toSend, myargs.Delay, sender, file);
                                        }
                                        catch (ArgumentOutOfRangeException)
                                        {
                                            Console.WriteLine(ErrorStrings.OutOfBoundsError);
                                        }

                                        toSend = "";
                                        idex++;
                                    }
                                }
                            }

                            // Does the search terms exist in this chunk in ASCII form?
                            if (memStringAscii.Contains(myargs.Searchterm))
                            {
                                int idex = 0;
                                while ((idex = memStringAscii.IndexOf(myargs.Searchterm, idex, StringComparison.Ordinal)) != -1)
                                {
                                    try
                                    {
                                        toSend += process.ProcessName + ":" + process.Id + ":0x" + (memBasicInfo.BaseAddress + idex) + ":A:" + memStringAscii.Substring(idex - myargs.Prepostfix, postfix) + "\n";
                                        OutputString(myargs.Mode, toSend, myargs.Delay, sender, file);
                                    }
                                    catch (ArgumentOutOfRangeException)
                                    {
                                        Console.WriteLine(ErrorStrings.OutOfBoundsError);
                                    }

                                    toSend = "";
                                    idex++;
                                }

                            }

                            // Does the search terms exist in this chunk in UNICODE form?
                            if (memStringUnicode.Contains(myargs.Searchterm))
                            {
                                int idex = 0;
                                while ((idex = memStringUnicode.IndexOf(myargs.Searchterm, idex, StringComparison.Ordinal)) != -1)
                                {
                                    try
                                    {
                                        toSend += process.ProcessName + ":" + process.Id + ":0x" + (memBasicInfo.BaseAddress + idex) + ":U:" + memStringUnicode.Substring(idex - myargs.Prepostfix, postfix) + "\n";
                                        OutputString(myargs.Mode, toSend, myargs.Delay, sender, file);
                                    }
                                    catch(ArgumentOutOfRangeException)
                                    {
                                        Console.WriteLine(ErrorStrings.OutOfBoundsError);
                                    }

                                    toSend = "";
                                    idex++;
                                }

                            }

                        }

                        // Truffle shuffle - moving on chunk.
                        procMinAddressL += memBasicInfo.RegionSize;
                        procMinAddress = new IntPtr(procMinAddressL);

                    }
                }
            }

            // ask Turing if we'll ever get here...
/*
            sender.Shutdown(SocketShutdown.Both);
            sender.Close();
            if (myargs.Mode.Equals("file"))
            {
                file.Close();
            }
*/
        }
    }
}