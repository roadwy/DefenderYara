
rule VirTool_Win32_VBInject_ACC{
	meta:
		description = "VirTool:Win32/VBInject.ACC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 50 41 40 00 ff d6 } //01 00 
		$a_01_1 = {68 98 47 40 00 ff d6 } //01 00 
		$a_01_2 = {50 65 70 65 72 6f 6e 69 26 50 72 65 73 69 64 65 6e 74 00 } //01 00 
		$a_00_3 = {42 00 72 00 6f 00 6b 00 65 00 6e 00 48 00 65 00 61 00 72 00 74 00 68 00 } //01 00 
		$a_00_4 = {4d 00 6f 00 74 00 6f 00 77 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}