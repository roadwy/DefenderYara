
rule VirTool_Win32_Cdknstubof_A{
	meta:
		description = "VirTool:Win32/Cdknstubof.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 75 6d 62 65 72 20 6f 66 20 61 72 67 75 6d 65 6e 74 73 } //01 00  number of arguments
		$a_01_1 = {53 48 45 4c 4c 43 4f 44 45 } //01 00  SHELLCODE
		$a_01_2 = {53 70 61 77 6e 69 6e 67 20 54 65 6d 70 6f 72 61 72 79 20 50 72 6f 63 65 73 73 } //01 00  Spawning Temporary Process
		$a_01_3 = {4f 70 65 6e 69 6e 67 20 45 78 69 73 74 69 6e 67 20 50 72 6f 63 65 73 73 } //01 00  Opening Existing Process
		$a_01_4 = {62 6f 66 73 74 6f 70 } //00 00  bofstop
	condition:
		any of ($a_*)
 
}