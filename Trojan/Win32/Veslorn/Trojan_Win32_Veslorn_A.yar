
rule Trojan_Win32_Veslorn_A{
	meta:
		description = "Trojan:Win32/Veslorn.A,SIGNATURE_TYPE_PEHSTR,65 00 65 00 0e 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 53 56 43 48 30 53 54 2e 45 58 45 } //0a 00  \SVCH0ST.EXE
		$a_01_1 = {5b 41 75 74 6f 72 75 6e 5d } //0a 00  [Autorun]
		$a_01_2 = {6f 70 65 6e 3d 25 73 } //0a 00  open=%s
		$a_01_3 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 25 73 } //0a 00  shellexecute=%s
		$a_01_4 = {73 68 65 6c 6c 5c 31 3d 4f 70 65 6e } //0a 00  shell\1=Open
		$a_01_5 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //0a 00  CreateRemoteThread
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //0a 00  WriteProcessMemory
		$a_01_7 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //0a 00  SeDebugPrivilege
		$a_01_8 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //0a 00  CreateToolhelp32Snapshot
		$a_01_9 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //01 00  AdjustTokenPrivileges
		$a_01_10 = {52 61 76 6d 6f 6e 44 2e 65 78 65 } //01 00  RavmonD.exe
		$a_01_11 = {52 61 76 6d 6f 6e 2e 65 78 65 } //01 00  Ravmon.exe
		$a_01_12 = {6b 61 76 73 76 63 2e 65 78 65 } //01 00  kavsvc.exe
		$a_01_13 = {61 76 70 2e 65 78 65 } //00 00  avp.exe
	condition:
		any of ($a_*)
 
}