Mnemosyne is a generic Windows-based memory scraping tool.

It scans a process memory space for a search string or regex (unicode and ascii) then if found, spits these out either to stdout, a file or a socket to a remote listener.

The utility is useful for memory scraping a process, as a post-exploitation POC, a dynamic analysis mechanism for malware, an instrumentation tool to be used during fuzzing and many other applications.

The tool works infinitely over a process (or all running processes) since memory is dynamic and subject to rapid change, hence this looping may be more beneficial for scraping specific items of interest within memory.

It uses only native Win32 API calls so no dependencies and has worked from Windows 2000 up to Windows 10 (compilation to different versions of .NET will be required for older platforms).

The main limitation is with Protected Processes - Mnemosyne will not be able to access the virtual memory of a protected process and so will skip any such process without scraping.

Run Mnemosyne.exe for full usage.
