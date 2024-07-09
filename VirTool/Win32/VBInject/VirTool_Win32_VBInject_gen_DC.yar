
rule VirTool_Win32_VBInject_gen_DC{
	meta:
		description = "VirTool:Win32/VBInject.gen!DC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 8d ac fe ff ff 8b 95 b8 fe ff ff [0-16] 89 8d 64 fe ff ff } //2
		$a_03_1 = {03 ca 8b 55 ?? 0f 80 ?? ?? ?? ?? 89 8a b0 00 00 00 } //2
		$a_01_2 = {c7 00 07 00 01 00 } //1
		$a_01_3 = {b9 59 00 00 00 ff 15 } //1
		$a_01_4 = {b9 c3 00 00 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}