
rule VirTool_Win32_VBInject_gen_HT{
	meta:
		description = "VirTool:Win32/VBInject.gen!HT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 04 82 07 00 01 00 } //01 00 
		$a_01_1 = {03 c2 89 81 b0 00 00 00 } //01 00 
		$a_01_2 = {3b c2 7f 0e c6 04 07 cc e9 } //01 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_VBInject_gen_HT_2{
	meta:
		description = "VirTool:Win32/VBInject.gen!HT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {bb e9 00 00 00 8b c1 83 c4 1c 99 f7 fb 8b c1 } //01 00 
		$a_03_1 = {05 f8 00 00 00 6a 28 0f 80 90 01 02 00 00 6b c9 28 90 00 } //01 00 
		$a_01_2 = {8d 85 30 fd ff ff 50 56 56 6a 04 56 56 56 8d 8d 14 fd ff ff } //00 00 
	condition:
		any of ($a_*)
 
}