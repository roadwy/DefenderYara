
rule VirTool_Win32_CeeInject_gen_AP{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b d8 48 85 c0 75 f9 0f 31 } //1
		$a_03_1 = {8d 04 95 04 00 00 00 39 85 ?? ?? ?? ?? 73 2d 8b 8d ?? ?? ?? ?? 8b 54 0d 0c 89 55 fc 8b 45 fc 33 45 08 89 45 fc } //1
		$a_01_2 = {81 39 50 45 00 00 74 07 33 c0 e9 } //1
		$a_01_3 = {8d 94 01 f8 00 00 00 89 95 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}