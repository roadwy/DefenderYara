
rule PWS_Win32_Fareit_F_MTB{
	meta:
		description = "PWS:Win32/Fareit.F!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 68 00 61 00 72 00 65 00 69 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  Shareit.exe
		$a_01_1 = {4d 00 69 00 75 00 73 00 79 00 4c 00 61 00 54 00 72 00 6f 00 69 00 6f 00 30 00 30 00 39 00 } //01 00  MiusyLaTroio009
		$a_01_2 = {4e 00 4f 00 4d 00 45 00 4c 00 4d 00 4f 00 5a 00 4f 00 } //01 00  NOMELMOZO
		$a_01_3 = {43 00 61 00 6c 00 6c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 50 00 72 00 6f 00 63 00 57 00 } //01 00  CallWindowProcW
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}