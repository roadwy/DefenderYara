
rule VirTool_Win32_VBInject_gen_HX{
	meta:
		description = "VirTool:Win32/VBInject.gen!HX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 04 88 07 00 01 00 } //01 00 
		$a_03_1 = {07 00 01 00 90 09 06 00 c7 85 90 00 } //01 00 
		$a_01_2 = {89 81 b0 00 00 00 } //01 00 
		$a_00_3 = {b9 c3 00 00 00 ff 15 } //04 00 
		$a_03_4 = {66 0f b6 0c 08 8b 95 90 01 02 ff ff 8b 45 90 01 01 66 33 0c 50 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}