
rule HackTool_Win32_Small_C{
	meta:
		description = "HackTool:Win32/Small.C,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 64 64 55 73 65 72 54 6f 47 72 6f 75 70 } //01 00  AddUserToGroup
		$a_01_1 = {42 2e 45 2e 4e 5f 44 75 63 6b } //01 00  B.E.N_Duck
		$a_01_2 = {73 00 65 00 74 00 68 00 63 00 2e 00 65 00 78 00 65 00 } //01 00  sethc.exe
		$a_01_3 = {41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 73 00 } //01 00  Administrators
		$a_01_4 = {74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  taskmgr.exe
	condition:
		any of ($a_*)
 
}