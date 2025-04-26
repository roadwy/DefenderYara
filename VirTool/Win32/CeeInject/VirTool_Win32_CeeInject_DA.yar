
rule VirTool_Win32_CeeInject_DA{
	meta:
		description = "VirTool:Win32/CeeInject.DA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b7 4d 08 03 c1 a3 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 47 2d 2f 03 00 00 4f 8b 00 03 c9 } //1
		$a_03_1 = {8b 55 08 83 ea 0a 39 55 f4 74 ?? 0f b7 05 ?? ?? ?? ?? 2b 45 08 0f b7 4d f4 03 c1 89 45 08 } //1
		$a_03_2 = {83 d6 00 0f b6 05 ?? ?? ?? ?? 99 03 c8 13 f2 89 0d ?? ?? ?? ?? 8a 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}