
rule VirTool_Win32_VBInject_gen_HP{
	meta:
		description = "VirTool:Win32/VBInject.gen!HP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 02 07 00 01 00 } //1
		$a_01_1 = {89 8a b0 00 00 00 } //1
		$a_03_2 = {8b 91 a4 00 00 00 [0-05] c7 85 ?? ?? ff ff 03 00 00 } //1
		$a_03_3 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 45 ?? 66 33 0c 50 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}