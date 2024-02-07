
rule PWS_Win32_Lmir_gen_M{
	meta:
		description = "PWS:Win32/Lmir.gen!M,SIGNATURE_TYPE_PEHSTR_EXT,ffffffa5 00 ffffff9b 00 12 00 00 19 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 48 6f 6f 6b } //19 00  StartHook
		$a_00_1 = {53 74 6f 70 48 6f 6f 6b } //19 00  StopHook
		$a_00_2 = {48 6f 73 74 3a } //19 00  Host:
		$a_00_3 = {50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65 } //19 00  Proxy-Connection: Keep-Alive
		$a_00_4 = {6d 69 72 2e 64 61 74 } //19 00  mir.dat
		$a_00_5 = {6d 69 72 2e 65 78 65 } //05 00  mir.exe
		$a_00_6 = {57 69 6e 45 78 65 63 } //05 00  WinExec
		$a_01_7 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //05 00  ReadProcessMemory
		$a_00_8 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //05 00  UnhookWindowsHookEx
		$a_01_9 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //05 00  SetWindowsHookExA
		$a_00_10 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //05 00  CallNextHookEx
		$a_00_11 = {57 53 41 53 74 61 72 74 75 70 } //05 00  WSAStartup
		$a_00_12 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //05 00  gethostbyname
		$a_00_13 = {73 6f 63 6b 65 74 } //05 00  socket
		$a_00_14 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //05 00  URLDownloadToFileA
		$a_01_15 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //05 00  CreateToolhelp32Snapshot
		$a_01_16 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //6a ff  Toolhelp32ReadProcessMemory
		$a_00_17 = {4f 6e 6c 79 20 72 65 67 69 73 74 65 72 65 64 20 76 65 72 73 69 6f 6e 20 6f 66 20 49 70 61 72 6d 6f 72 20 63 61 6e 20 63 6c 65 61 6e } //00 00  Only registered version of Iparmor can clean
	condition:
		any of ($a_*)
 
}