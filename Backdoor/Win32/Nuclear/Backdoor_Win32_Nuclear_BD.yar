
rule Backdoor_Win32_Nuclear_BD{
	meta:
		description = "Backdoor:Win32/Nuclear.BD,SIGNATURE_TYPE_PEHSTR,ffffff9b 00 ffffff9b 00 0d 00 00 64 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {54 4a 75 73 74 53 63 61 6e } //0a 00  TJustScan
		$a_01_2 = {54 54 43 50 54 75 6e 6e 65 6c 34 } //0a 00  TTCPTunnel4
		$a_01_3 = {4e 75 63 6c 65 61 72 20 52 41 54 20 57 65 62 53 65 72 76 65 72 } //0a 00  Nuclear RAT WebServer
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 75 63 6c 65 61 72 77 69 6e 74 65 72 2e 75 73 } //0a 00  http://www.nuclearwinter.us
		$a_01_5 = {6a 61 76 61 73 63 72 69 70 74 3a 68 69 73 74 6f 72 79 2e 67 6f 28 2d 31 29 3b } //01 00  javascript:history.go(-1);
		$a_01_6 = {6c 69 73 74 65 6e } //01 00  listen
		$a_01_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_8 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //01 00  SeShutdownPrivilege
		$a_01_9 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //01 00  InternetOpenA
		$a_01_10 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00  InternetReadFile
		$a_01_11 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_01_12 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  Toolhelp32ReadProcessMemory
	condition:
		any of ($a_*)
 
}