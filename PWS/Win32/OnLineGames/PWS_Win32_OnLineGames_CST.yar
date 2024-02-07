
rule PWS_Win32_OnLineGames_CST{
	meta:
		description = "PWS:Win32/OnLineGames.CST,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 73 61 65 6e 68 2e 64 72 73 61 65 6e 68 2e 64 6c 6c } //01 00  rsaenh.drsaenh.dll
		$a_00_1 = {2e 5c 74 65 6e 69 6f 5c 74 65 6e 73 67 2e 44 4c 4c } //01 00  .\tenio\tensg.DLL
		$a_00_2 = {6c 69 76 65 75 70 64 61 74 65 2e 45 58 45 } //01 00  liveupdate.EXE
		$a_00_3 = {47 74 53 61 6c 6f 6f 6e 2e 65 78 65 } //01 00  GtSaloon.exe
		$a_00_4 = {2e 5c 71 71 73 67 2e 65 78 65 } //01 00  .\qqsg.exe
		$a_00_5 = {77 6f 77 2e 65 78 65 } //01 00  wow.exe
		$a_01_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_01_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}