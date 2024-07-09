
rule VirTool_Win32_CeeInject_gen_DX{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 39 07 0f 85 ?? ?? ?? ?? 8b 47 3c 03 c7 a3 ?? ?? ?? ?? 81 38 50 45 00 00 0f 85 8f 01 00 00 68 ?? ?? ?? ?? ff 15 } //1
		$a_03_1 = {39 74 24 0c 7c 1f 8b 44 24 08 8d 0c 06 8b c6 99 f7 3d ?? ?? ?? ?? 8a 82 ?? ?? ?? ?? 30 01 46 3b 74 24 0c 7e e1 5e c3 } //1
		$a_03_2 = {8d 4d 08 51 6a 40 53 50 89 06 ff 15 ?? ?? ?? ?? 8b 5d 0c 57 53 ff 36 e8 ?? ?? ?? ?? 01 3e 8b 06 c6 00 e9 83 c4 0c ff 06 8b 06 8b cf 2b c8 8d 4c 19 fc 89 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}