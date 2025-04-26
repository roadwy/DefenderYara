
rule VirTool_Win32_CeeInject_NK_bit{
	meta:
		description = "VirTool:Win32/CeeInject.NK!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 45 fc 0f b6 00 3d cc 00 00 00 74 0d 8b 45 fc 0f b6 00 3d 90 00 00 00 75 06 } //1
		$a_03_1 = {89 4d 94 81 7d 94 31 33 24 72 74 1d [0-30] ff 55 a4 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CeeInject_NK_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.NK!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 89 85 ?? ?? ?? ?? 8b 4d ec 03 8d ?? ?? ?? ?? 8b 55 f4 03 95 ?? ?? ?? ?? 8a 02 88 01 8b 4d f8 83 c1 01 89 4d f8 eb } //1
		$a_03_1 = {89 45 f8 8b 0d ?? ?? ?? ?? 89 4d f8 8b 45 f8 31 45 fc 8b 55 fc 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 8b e5 } //1
		$a_03_2 = {8b f6 ff 35 ?? ?? ?? ?? 8b f6 33 d2 8d 05 ?? ?? ?? ?? 48 03 10 8b c9 8b c9 8b c9 ff e2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}