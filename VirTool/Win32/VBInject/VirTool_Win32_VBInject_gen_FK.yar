
rule VirTool_Win32_VBInject_gen_FK{
	meta:
		description = "VirTool:Win32/VBInject.gen!FK,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 04 00 "
		
	strings :
		$a_03_0 = {8b 91 a4 00 00 00 90 03 02 00 90 13 c7 85 90 01 08 83 c2 08 90 02 06 89 95 90 00 } //01 00 
		$a_01_1 = {89 81 b0 00 00 00 } //01 00 
		$a_01_2 = {89 8a b0 00 00 00 } //01 00 
		$a_01_3 = {68 95 e3 35 69 } //01 00 
		$a_01_4 = {c7 02 07 00 01 00 } //01 00 
		$a_01_5 = {68 c2 8c 10 c5 68 } //01 00 
	condition:
		any of ($a_*)
 
}