
rule Backdoor_Win32_Delfsnif_B{
	meta:
		description = "Backdoor:Win32/Delfsnif.B,SIGNATURE_TYPE_PEHSTR,56 01 56 01 0c 00 00 64 00 "
		
	strings :
		$a_01_0 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //64 00  SeDebugPrivilege
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //64 00  WriteProcessMemory
		$a_01_2 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //0a 00  ZwQuerySystemInformation
		$a_01_3 = {64 65 6c 20 2e 5c 64 65 6c 6d 65 64 6c 6c 2e 62 61 74 } //0a 00  del .\delmedll.bat
		$a_01_4 = {64 65 6c 6d 65 65 78 65 2e 62 61 74 20 67 6f 74 6f 20 6c 6f 6f 70 } //0a 00  delmeexe.bat goto loop
		$a_01_5 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //0a 00  \Device\PhysicalMemory
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_7 = {6b 6c 6a 73 70 61 73 73 3a } //01 00  kljspass:
		$a_01_8 = {6d 65 6e 61 6d 65 65 78 65 3a } //01 00  menameexe:
		$a_01_9 = {6d 65 6e 61 6d 65 64 6c 6c 3a } //01 00  menamedll:
		$a_01_10 = {65 78 65 66 69 6c 65 3a } //01 00  exefile:
		$a_01_11 = {64 6c 6c 66 69 6c 65 3a } //00 00  dllfile:
	condition:
		any of ($a_*)
 
}