
rule VirTool_Win32_VBInject_gen_GZ{
	meta:
		description = "VirTool:Win32/VBInject.gen!GZ,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {03 85 84 fe ff ff [0-06] 89 85 40 fe ff ff 90 09 06 00 8b 85 90 90 fe ff ff } //1
		$a_03_1 = {8b 85 a0 fe ff ff 03 85 94 fe ff ff [0-06] 89 85 4c fe ff ff } //1
		$a_03_2 = {9c fe ff ff 03 ?? 90 90 fe ff ff 89 ?? 48 fe ff ff } //1
		$a_03_3 = {07 00 01 00 90 09 06 00 c7 85 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*10) >=11
 
}