
rule VirTool_Win32_VBInject_ACD{
	meta:
		description = "VirTool:Win32/VBInject.ACD,SIGNATURE_TYPE_PEHSTR,0a 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 5c 00 41 00 4c 00 3a 00 5c 01 4a 00 61 00 63 00 6b 00 69 00 6e 00 74 00 68 00 5c 01 4a 00 61 00 63 00 6b 00 69 00 6e 00 74 00 68 00 31 00 2e 00 76 00 62 00 70 } //01 00 
		$a_01_1 = {48 4f 53 54 41 4c 68 6f 48 4f 53 54 41 4c 68 6f 21 5c 48 4f 53 54 41 4c 68 6f 00 6a 70 67 00 } //01 00 
		$a_01_2 = {4a 00 61 00 63 00 6b 00 69 00 6e 00 74 00 68 00 2e 00 65 00 78 00 65 00 } //00 00  Jackinth.exe
	condition:
		any of ($a_*)
 
}