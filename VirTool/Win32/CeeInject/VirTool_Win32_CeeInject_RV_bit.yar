
rule VirTool_Win32_CeeInject_RV_bit{
	meta:
		description = "VirTool:Win32/CeeInject.RV!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 fc 0f 1f 84 00 00 00 00 00 55 89 e5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule VirTool_Win32_CeeInject_RV_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.RV!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 11 8b 45 ?? 03 45 ?? 0f b6 08 03 d1 81 e2 ?? ?? ?? ?? 79 90 09 09 00 83 c4 ?? 8b 4d ?? 03 4d } //1
		$a_03_1 = {8b c1 8b d1 03 c6 3b fe 76 08 3b f8 0f 82 ?? ?? ?? ?? 83 f9 ?? 0f 82 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 73 13 0f ba 25 ?? ?? ?? ?? 01 0f 82 ?? ?? ?? ?? e9 ?? ?? ?? ?? 0f ba 25 ?? ?? ?? ?? 01 73 09 f3 a4 } //1
		$a_03_2 = {8b 06 03 d0 83 f0 ?? 33 c2 8b 16 83 c6 04 a9 ?? ?? ?? ?? 74 dc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}