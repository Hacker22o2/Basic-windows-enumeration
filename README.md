# Basic Windows enumertion script

This is Powershell script desgined for penetration testers, CTFers and specially for OSCP to enumeration information for particular Windows Target machine. 

Usage:
Download this script.

Run from within CMD shell and write out to file.
CMD C:\Users\user\Downloads\Basic-windows-enumeration> powershell.exe -ExecutionPolicy Bypass -File .\Basic-windows-enumeration.ps1 -OutputFilename Basic-windows-enumeration_Results.txt

Run from within CMD shell and write out to screen.
CMD C:\Users\user\Downloads\Basic-windows-enumeration> powershell.exe -ExecutionPolicy Bypass -File .\Basic-windows-enumeration.ps1 

Run from within PS Shell and write out to file.
PS C:\Users\user\Downloads\Basic-windows-enumeration> .\Basic-windows-enumeration.ps1 -OutputFileName Basic-windows-enumeration_Results.txt

Run from within CMD shell and write out to screen.
PS C:\Users\user\Downloads\Basic-windows-enumeration> .\Basic-windows-enumeration.ps1

Run by just right click on file and select run with powershell :)


# Current Features 
1.  Target System Information
2.  Network Information (interfaces, arp, netstat)
3.  Routing Tables
4.  Environment Variables
5.  Connected Drives
6.  Firewall Config
7.  Credentials Manager
8.  Local Group and Administrators
9.  User directories
10. Sam Backup Files
11. Installed Software Directories
12. Softwares in Registry
13. Folder Permissions
14. Unquoted Service Paths
15. Scheduled Tasks
16. Startup Programs
17. Hosts File Content
18. Running Services
19. AlwaysInstallElevated Registry Key Check
20. Recent Used programs
21. Modified Items
22. Stored Credentials
23. User Privilege 
24. Logged in User
25. Local Users
26. Current Users
27. Running Processes



