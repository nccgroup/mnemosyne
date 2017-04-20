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
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using MemoryScanner.Resources;

namespace MemoryScanner
{
    internal class ProcessSearch
    {
        public CliArgs MyArgs { get; set; }
        public Process Process { get; set; }
        public Socket Sender { get; set; }
        public StreamWriter File { get; set; }

        internal ProcessSearch(CliArgs myargs, Process process, Socket sender, StreamWriter file)
        {
            MyArgs = myargs;
            Process = process;
            Sender = sender;
            File = file;
        }

        internal void SearchProcessForString()
        {
            // Getting minimum & maximum address.
            ProgObj.SystemInfo sysInfo = new ProgObj.SystemInfo();
            ProgObj.GetSystemInfo(out sysInfo);

            IntPtr procMinAddress = sysInfo.MinimumApplicationAddress;
            IntPtr procMaxAddress = sysInfo.MaximumApplicationAddress;

            // Saving the values as long ints to avoid lot of casts later.
            long procMinAddressL = (long) procMinAddress;
            long procMaxAddressL = (long) procMaxAddress;

            string toSend = "";

            // Opening the Process with desired access level.
            IntPtr processHandle = ProgObj.OpenProcess(ProgObj.ProcessQueryInformation | ProgObj.ProcessWmRead, false,
                Process.Id);

            // We don't want to scrape our own Process and if we can't get a handle then it's probalby a protected Process.
            // So don't try and scan it otherwise Mnemosyne will stall.
            if (Process.Id == Process.GetCurrentProcess().Id || processHandle == IntPtr.Zero) return;

            Console.WriteLine(MessageStrings.ProcessIdMessage, Process.Id, Process.ProcessName);

            // This will store any information we get from VirtualQueryEx().
            ProgObj.MemoryBasicInformation memBasicInfo = new ProgObj.MemoryBasicInformation();

            // Number of bytes read with ReadProcessMemory.
            int bytesRead = 0;

            // For some efficiencies, pre-compute prepostfix values.
            int postfix = MyArgs.Searchterm.Length + (MyArgs.Prepostfix * 2);

            while (procMinAddressL < procMaxAddressL)
            {
                // 28 = sizeof(MEMORY_BASIC_INFORMATION)
                ProgObj.VirtualQueryEx(processHandle, procMinAddress, out memBasicInfo, 28);

                // If this memory chunk is accessible.
                if (memBasicInfo.Protect == ProgObj.PageReadwrite && memBasicInfo.State == ProgObj.MemCommit)
                    bytesRead = HandleAccessibleMemoryChunk(memBasicInfo, processHandle, bytesRead, postfix, ref toSend);

                // Truffle shuffle - moving on chunk.
                procMinAddressL += memBasicInfo.RegionSize;
                procMinAddress = new IntPtr(procMinAddressL);
            }
        }

        private int HandleAccessibleMemoryChunk(ProgObj.MemoryBasicInformation memBasicInfo, IntPtr processHandle, int bytesRead, int postfix, ref string toSend)
        {
            byte[] buffer = new byte[memBasicInfo.RegionSize];

            // Read everything in the buffer above.
            ProgObj.ReadProcessMemory((int) processHandle, memBasicInfo.BaseAddress, buffer, memBasicInfo.RegionSize,
                ref bytesRead);

            string memStringAscii = Encoding.ASCII.GetString(buffer);
            string memStringUnicode = Encoding.Unicode.GetString(buffer);

            if (MyArgs.IsRegex)
                HandleRegexArgument(memBasicInfo, postfix, ref toSend, memStringAscii, memStringUnicode);

            // Does the search terms exist in this chunk in ASCII form?
            if (memStringAscii.Contains(MyArgs.Searchterm))
                HandleAsciiArgument(memBasicInfo, postfix, ref toSend, memStringAscii);

            // Does the search terms exist in this chunk in UNICODE form?
            if (memStringUnicode.Contains(MyArgs.Searchterm))
                HandleUnicodeArgument(memBasicInfo, postfix, ref toSend, memStringUnicode);

            return bytesRead;
        }

        private void HandleUnicodeArgument(ProgObj.MemoryBasicInformation memBasicInfo, int postfix, ref string toSend, string memStringUnicode)
        {
            int idex = 0;
            while ((idex = memStringUnicode.IndexOf(MyArgs.Searchterm, idex, StringComparison.Ordinal)) != -1)
            {
                try
                {
                    toSend += Process.ProcessName + ":" + Process.Id + ":0x" + (memBasicInfo.BaseAddress + idex) +
                              ":U:" + memStringUnicode.Substring(idex - MyArgs.Prepostfix, postfix) + "\n";
                    ProgObj.OutputString(MyArgs.Mode, toSend, MyArgs.Delay, Sender, File);
                }
                catch (ArgumentOutOfRangeException)
                {
                    Console.WriteLine(ErrorStrings.OutOfBoundsError);
                }

                toSend = "";
                idex++;
            }
        }

        private void HandleAsciiArgument(ProgObj.MemoryBasicInformation memBasicInfo, int postfix, ref string toSend, string memStringAscii)
        {
            int idex = 0;
            while ((idex = memStringAscii.IndexOf(MyArgs.Searchterm, idex, StringComparison.Ordinal)) != -1)
            {
                try
                {
                    toSend += Process.ProcessName + ":" + Process.Id + ":0x" + (memBasicInfo.BaseAddress + idex) +
                              ":A:" + memStringAscii.Substring(idex - MyArgs.Prepostfix, postfix) + "\n";
                    ProgObj.OutputString(MyArgs.Mode, toSend, MyArgs.Delay, Sender, File);
                }
                catch (ArgumentOutOfRangeException)
                {
                    Console.WriteLine(ErrorStrings.OutOfBoundsError);
                }

                toSend = "";
                idex++;
            }
        }

        private void HandleRegexArgument(ProgObj.MemoryBasicInformation memBasicInfo, int postfix, ref string toSend, string memStringAscii, string memStringUnicode)
        {
            Regex rgx = new Regex(MyArgs.Searchterm, RegexOptions.IgnoreCase);

            // Does the regex pattern exist in this chunk in ASCII form?
            if (rgx.IsMatch(memStringAscii))
                HandleRegexMatching("A", memBasicInfo, postfix, ref toSend, memStringUnicode, rgx);

            // Does the regex pattern exist in this chunk in UNICODE form?
            if (rgx.IsMatch(memStringUnicode))
                HandleRegexMatching("U", memBasicInfo, postfix, ref toSend, memStringUnicode, rgx);
        }

        private void HandleRegexMatching(string encodingFormat, ProgObj.MemoryBasicInformation memBasicInfo, int postfix, ref string toSend,
            string memStringUnicode, Regex rgx)
        {
            int idex = 0;
            while (rgx.Match(memStringUnicode, idex).Success)
            {
                idex = rgx.Match(memStringUnicode, idex).Index;
                try
                {
                    toSend += Process.ProcessName + ":" + Process.Id + ":0x" +
                              (memBasicInfo.BaseAddress + idex) + ":" + encodingFormat + ":" +
                              memStringUnicode.Substring(idex - MyArgs.Prepostfix, postfix) + "\n";
                    ProgObj.OutputString(MyArgs.Mode, toSend, MyArgs.Delay, Sender, File);
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
}