
rule Backdoor_Win32_Delfsnif_gen_F{
	meta:
		description = "Backdoor:Win32/Delfsnif.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc2 01 ffffffa9 01 13 00 00 64 00 "
		
	strings :
		$a_00_0 = {72 00 70 00 63 00 73 00 2e 00 65 00 78 00 65 00 } //64 00  rpcs.exe
		$a_01_1 = {47 00 65 00 6e 00 65 00 72 00 69 00 63 00 20 00 48 00 6f 00 73 00 74 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 66 00 6f 00 72 00 20 00 57 00 69 00 6e 00 33 00 32 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 } //32 00  Generic Host Process for Win32 Services
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //32 00  SOFTWARE\Borland\Delphi
		$a_00_3 = {46 47 49 6e 74 52 53 41 } //19 00  FGIntRSA
		$a_00_4 = {46 48 69 64 65 50 72 6f 63 65 73 73 } //19 00  FHideProcess
		$a_00_5 = {76 48 69 64 65 50 72 6f 63 65 73 73 } //19 00  vHideProcess
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //19 00  WriteProcessMemory
		$a_01_7 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //0a 00  Toolhelp32ReadProcessMemory
		$a_00_8 = {64 65 6c 6d 65 64 6c 6c 2e 62 61 74 } //0a 00  delmedll.bat
		$a_00_9 = {64 65 6c 6d 65 65 78 65 2e 62 61 74 } //0a 00  delmeexe.bat
		$a_00_10 = {64 65 6c 20 2e 5c 64 65 6c 6d 65 64 6c 6c 2e 62 61 74 } //0a 00  del .\delmedll.bat
		$a_00_11 = {63 6d 64 2e 65 78 65 } //0a 00  cmd.exe
		$a_00_12 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //0a 00  Internet Explorer
		$a_00_13 = {4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e } //0a 00  OpenProcessToken
		$a_00_14 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //0a 00  AdjustTokenPrivileges
		$a_00_15 = {57 69 6e 45 78 65 63 } //0a 00  WinExec
		$a_01_16 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //0a 00  SeShutdownPrivilege
		$a_00_17 = {4c 6f 6f 6b 75 70 50 72 69 76 69 6c 65 67 65 56 61 6c 75 65 41 } //0a 00  LookupPrivilegeValueA
		$a_00_18 = {57 69 6e 73 6f 63 6b 32 46 6c 6f 6f 64 } //00 00  Winsock2Flood
	condition:
		any of ($a_*)
 
}