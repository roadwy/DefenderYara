
rule VirTool_Win32_CeeInject_SV_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SV!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 11 8b 45 fc 03 45 ?? 0f b6 08 8d 54 11 02 8b 45 fc 03 45 ?? 88 10 8b 4d fc 03 4d ?? 0f b6 11 83 ea 02 8b 45 fc 03 45 ?? 88 10 c7 45 f0 ?? ?? ?? 00 8b 4d f8 83 c1 01 89 4d f8 e9 43 ff ff ff } //1
		$a_01_1 = {8b 55 08 8b 02 03 45 fc 8b 4d 08 89 01 8b e5 5d c3 } //1
		$a_03_2 = {8b ca 33 c1 [0-30] 89 11 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule VirTool_Win32_CeeInject_SV_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.SV!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff ff ff 24 03 00 00 73 52 8b ?? ?? ff ff ff 8b ?? ?? ?? ?? 41 00 89 ?? ?? ff ff ff 8b ?? ?? ff ff ff 2b ?? ?? ff ff ff 89 ?? ?? ff ff ff c1 85 ?? ff ff ff 0f 8b ?? ?? ff ff ff 33 ?? ?? ?? 41 00 89 ?? ?? ff ff ff 8b ?? ?? ff ff ff 8b ?? ?? 8b ?? ?? ff ff ff 89 ?? ?? eb 93 } //2
		$a_03_1 = {24 03 00 00 73 33 8b 45 ?? 8b 4d ?? 8b 14 81 89 55 ?? 8b 45 ?? 2b 45 ?? 89 45 ?? c1 45 ?? 0f 8b 4d ?? 33 0d ?? ?? ?? ?? 89 4d ?? 8b 55 ?? 8b 45 ?? 8b 4d ?? 89 0c 90 90 eb bb } //2
		$a_01_2 = {68 b8 88 00 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}