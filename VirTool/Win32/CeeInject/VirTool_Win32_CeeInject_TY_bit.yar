
rule VirTool_Win32_CeeInject_TY_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TY!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d0 83 e2 03 8a 14 0a 30 14 38 40 3b c6 72 f0 } //01 00 
		$a_01_1 = {8b c3 c1 e8 08 8b d3 88 19 c1 eb 18 88 41 01 c1 ea 10 33 c0 88 59 03 88 51 02 } //01 00 
		$a_03_2 = {0f af c6 03 c0 03 c0 03 c0 bb 90 01 04 6a 01 2b d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_TY_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TY!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8b 4d 18 03 4d f0 0f b6 09 33 8c 85 90 01 03 ff 8b 45 18 03 45 f0 88 08 90 00 } //01 00 
		$a_03_1 = {8b 4d 08 03 48 10 89 4d 90 01 01 e8 90 01 03 00 6a 00 ff 75 0c ff 75 08 ff 55 90 01 01 89 45 90 01 01 e8 90 01 03 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}