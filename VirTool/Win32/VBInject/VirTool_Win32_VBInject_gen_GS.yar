
rule VirTool_Win32_VBInject_gen_GS{
	meta:
		description = "VirTool:Win32/VBInject.gen!GS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 81 b0 00 00 00 } //01 00 
		$a_01_1 = {26 00 48 00 35 00 39 00 35 00 39 00 35 00 39 00 35 00 38 00 } //01 00  &H59595958
		$a_03_2 = {03 82 a4 00 00 00 0f 80 90 01 04 89 85 90 01 04 8b 85 90 01 04 c7 85 90 01 04 03 00 00 00 8b 48 14 c1 e1 04 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}