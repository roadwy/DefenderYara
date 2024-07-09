
rule VirTool_Win32_CeeInject_gen_KA{
	meta:
		description = "VirTool:Win32/CeeInject.gen!KA,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 8b ?? ?? ?? ?? ?? 8b ?? 50 ?? 8b ?? 90 1b 01 8b ?? 34 } //1
		$a_03_1 = {68 00 30 00 00 8b 15 ?? ?? ?? ?? 8b 42 50 50 8b 0d ?? ?? ?? ?? 8b 51 34 } //1
		$a_03_2 = {8b 48 34 8b 15 ?? ?? ?? ?? 03 4a 28 89 0d } //2
		$a_01_3 = {8d 94 01 f8 00 00 00 } //2
		$a_03_4 = {0f be 11 0f be 85 ?? ?? ff ff 33 d0 8b 4d ?? 03 8d ?? ?? ff ff 88 11 e9 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2+(#a_03_4  & 1)*2) >=7
 
}