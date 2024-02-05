
rule VirTool_Win32_VBInject_gen_CD{
	meta:
		description = "VirTool:Win32/VBInject.gen!CD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 85 8c fe ff ff 03 85 80 fe ff ff 0f 80 90 01 02 00 00 89 85 f4 fd ff ff 90 00 } //01 00 
		$a_03_1 = {8b 85 a8 fe ff ff 03 85 9c fe ff ff 0f 80 90 01 02 00 00 89 85 90 01 01 fe ff ff 90 00 } //01 00 
		$a_03_2 = {8b 85 88 fe ff ff 03 85 7c fe ff ff 0f 80 90 01 02 00 00 89 85 f0 fd ff ff 90 00 } //01 00 
		$a_03_3 = {8b 85 dc fe ff ff 03 85 58 fd ff ff 90 02 06 89 85 90 90 fe ff ff 90 00 } //04 00 
		$a_03_4 = {66 b9 c3 00 90 01 11 66 b9 cc 00 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}