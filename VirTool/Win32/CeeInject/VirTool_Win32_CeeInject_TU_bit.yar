
rule VirTool_Win32_CeeInject_TU_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TU!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 db 33 db a1 ?? ?? ?? ?? 03 c3 8a 00 ?? ?? ?? ?? 89 db ?? ?? ?? ?? ?? ?? ?? ?? 34 16 8b 15 ?? ?? ?? ?? 03 d3 88 02 89 c0 } //1
		$a_00_1 = {8b c1 33 d2 52 50 8b c3 99 03 04 24 13 54 24 04 83 c4 08 8a 00 50 8b c7 33 d2 52 50 8b c3 99 03 04 24 13 54 24 04 83 c4 08 5a 88 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CeeInject_TU_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TU!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff d7 8b d6 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 04 0e 46 3b 74 24 0c 72 } //1
		$a_03_1 = {6a 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b cf 8b c7 c1 e9 05 03 4d ?? c1 e0 04 03 45 ?? 33 c8 8d 04 3e 33 c8 2b d9 8b cb 8b c3 c1 e9 05 03 4d ?? c1 e0 04 03 45 ?? 33 c8 8d 04 1e 33 c8 8d b6 ?? ?? ?? ?? 2b f9 83 6d fc 01 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}