
rule Worm_Win32_Locksky_gen_A{
	meta:
		description = "Worm:Win32/Locksky.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,ffffffff 00 ffffffe6 00 13 00 00 64 00 "
		
	strings :
		$a_00_0 = {7a 61 6c 75 70 61 } //19 00  zalupa
		$a_00_1 = {64 77 4d 61 67 69 63 3a 20 25 58 } //19 00  dwMagic: %X
		$a_00_2 = {72 77 78 2d 2d 2d 2d 2d 2d 20 31 20 75 73 65 72 20 67 72 6f 75 70 } //19 00  rwx------ 1 user group
		$a_00_3 = {64 72 77 78 2d 2d 2d 2d 2d 2d 20 31 20 75 73 65 72 20 67 72 6f 75 70 } //19 00  drwx------ 1 user group
		$a_00_4 = {48 6f 73 74 3a } //19 00  Host:
		$a_00_5 = {50 72 6f 78 79 2d 43 6f 6e 6e } //19 00  Proxy-Conn
		$a_00_6 = {53 65 72 76 65 72 3a 20 25 73 2c 20 4f 62 6a 3a 20 25 73 } //0a 00  Server: %s, Obj: %s
		$a_00_7 = {55 4e 4c 49 4e 4b } //0a 00  UNLINK
		$a_00_8 = {4c 49 4e 4b } //0a 00  LINK
		$a_00_9 = {50 4f 53 54 } //05 00  POST
		$a_00_10 = {57 69 6e 45 78 65 63 } //05 00  WinExec
		$a_00_11 = {4e 74 4f 70 65 6e 50 72 6f 63 65 73 73 } //05 00  NtOpenProcess
		$a_01_12 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //05 00  WriteProcessMemory
		$a_00_13 = {4e 74 46 72 65 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //05 00  NtFreeVirtualMemory
		$a_00_14 = {52 61 73 45 6e 75 6d 43 6f 6e 6e 65 63 74 69 6f 6e 73 41 } //05 00  RasEnumConnectionsA
		$a_01_15 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //05 00  NtQuerySystemInformation
		$a_00_16 = {4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //01 00  NtAllocateVirtualMemory
		$a_00_17 = {6e 65 74 66 69 6c 74 65 72 2e 64 6c 6c } //01 00  netfilter.dll
		$a_00_18 = {66 40 67 64 69 70 6c 75 73 2e 64 6c 6c } //00 00  f@gdiplus.dll
	condition:
		any of ($a_*)
 
}