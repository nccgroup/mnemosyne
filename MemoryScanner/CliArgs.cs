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
using System.Net;
using MemoryScanner.Resources;

namespace MemoryScanner
{
    // Container for command-line arguments with basic validator.
    internal class CliArgs
    {
        public int Pid = -1;
        public bool ProcHop;
        public string Ipaddr = "";
        public string Filename = "";
        public int Portnum = -1;
        public int Delay = -1;
        public string Searchterm = "";
        public string Mode = "";
        public int Prepostfix = -1;
        public bool IsRegex;

        public void SetMode(string value)
        {
            Mode = value;
        }

        public void SetPid(string value)
        {
            if (value == "-proc-hop")
            {
                ProcHop = true;
                Pid = 0;
            }
            else {
                int.TryParse(value, out Pid);
            }
        }

        public void SetIPaddr(string value)
        {
            Ipaddr = value;
        }

        public void SetFilename(string value)
        {
            Filename = value;
        }

        public void SetPortnum(string value)
        {
            int.TryParse(value, out Portnum);
        }

        public void SetDelay(string value)
        {
            int.TryParse(value, out Delay);
        }

        public void SetPrePostFix(string value)
        {
            int.TryParse(value, out Prepostfix);
        }

        // Get the search term.
        // Might be a string separated by spaces on the command line.
        public void DefineSearchTerm(string[] args, int offset)
        {
            for (int i = offset; i < args.Length; i++)
            {
                if (i != args.Length - 1)
                {
                    Searchterm += args[i] + " ";
                }
                else
                {
                    Searchterm += args[i];
                }
            }

            // Is string a regular expression?
            if (!Searchterm.StartsWith("~R")) return;

            IsRegex = true;
            
            // Remove our regex identifier "~R" from the start of the string.
            Searchterm = Searchterm.Remove(0, 2);
        }

        public bool IsArgumentValid()
        {
            if (Mode.Equals("stdio"))
                return Pid != -1 && Delay != -1 && Prepostfix != -1 && !Searchterm.Equals("");

            if (Mode.Equals("file"))
                return Pid != -1 && Delay != -1 && Prepostfix != -1 && !Searchterm.Equals("") && !Filename.Equals("");

            if (!Mode.Equals("socket")) return false;

            if (Pid == -1 || Delay == -1 || Prepostfix == -1 || Searchterm.Equals("") || Ipaddr.Equals("") || Portnum == -1)
                return false;

            try
            {
                IPAddress.Parse(Ipaddr);
            }
            catch (Exception)
            {
                Console.WriteLine(ErrorStrings.InvalidIpError);
                return false;
            }

            return true;
        }

    }

    // main program class
}
