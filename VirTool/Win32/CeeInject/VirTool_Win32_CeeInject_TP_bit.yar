
rule VirTool_Win32_CeeInject_TP_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 37 5b f8 83 df fc f7 d3 83 eb 23 8d 5b ff 29 d3 89 da 89 1e f8 83 d6 04 83 c1 fc 85 c9 75 e0 } //1
		$a_01_1 = {5e 8d 05 04 10 49 00 ff 30 ff d6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CeeInject_TP_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 04 3e 6a 00 90 09 05 00 e8 ?? ff ff ff } //1
		$a_03_1 = {8b c8 0f af 0d ?? ?? ?? ?? e8 ?? ff ff ff 03 c8 89 0d ?? ?? ?? ?? e8 ?? ff ff ff 0f b7 15 ?? ?? ?? ?? 23 c2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CeeInject_TP_bit_3{
	meta:
		description = "VirTool:Win32/CeeInject.TP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c3 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 83 c4 08 8b d1 8a 12 80 f2 81 88 10 ff 06 41 81 3e 2e 5b 00 00 75 } //1
		$a_03_1 = {55 8b ec 51 81 c2 4a 53 00 00 89 55 fc 8b 7d fc [0-10] 87 fb ff e3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CeeInject_TP_bit_4{
	meta:
		description = "VirTool:Win32/CeeInject.TP!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 11 8b 0c 24 81 c1 33 f9 03 59 89 4c 24 ?? 8b 4c 24 ?? 88 14 01 } //1
		$a_03_1 = {89 54 24 7c 8b 96 ?? ?? ?? ?? 8b 9c 24 ?? 00 00 00 8b b6 ?? ?? ?? ?? 31 fe 81 f3 ?? ?? ?? ?? 8b 7c 24 ?? 01 c7 } //1
		$a_03_2 = {89 c8 31 d2 8b 74 24 ?? f7 f6 8b 7c 24 ?? 8a 1c 0f 2a 1c 15 ?? ?? ?? ?? 8b 54 24 ?? 88 1c 0a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}