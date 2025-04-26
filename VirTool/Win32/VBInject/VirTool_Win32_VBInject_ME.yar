
rule VirTool_Win32_VBInject_ME{
	meta:
		description = "VirTool:Win32/VBInject.ME,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 c3 f8 00 00 00 8b 0e 0f 80 ?? ?? ?? ?? 6b c0 28 0f 80 ?? ?? ?? ?? 03 d8 } //1
		$a_03_1 = {80 fb 09 76 13 66 33 c9 8a cb 66 83 e9 07 0f 80 ?? ?? ?? ?? ff d7 8a d8 8a 45 e0 3c 09 76 14 } //1
		$a_01_2 = {c7 45 a8 e8 00 00 00 89 7d a0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}