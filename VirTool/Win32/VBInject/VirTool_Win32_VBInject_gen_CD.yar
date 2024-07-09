
rule VirTool_Win32_VBInject_gen_CD{
	meta:
		description = "VirTool:Win32/VBInject.gen!CD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 85 8c fe ff ff 03 85 80 fe ff ff 0f 80 ?? ?? 00 00 89 85 f4 fd ff ff } //1
		$a_03_1 = {8b 85 a8 fe ff ff 03 85 9c fe ff ff 0f 80 ?? ?? 00 00 89 85 ?? fe ff ff } //1
		$a_03_2 = {8b 85 88 fe ff ff 03 85 7c fe ff ff 0f 80 ?? ?? 00 00 89 85 f0 fd ff ff } //1
		$a_03_3 = {8b 85 dc fe ff ff 03 85 58 fd ff ff [0-06] 89 85 90 90 fe ff ff } //1
		$a_03_4 = {66 b9 c3 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 b9 cc 00 } //4
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*4) >=5
 
}