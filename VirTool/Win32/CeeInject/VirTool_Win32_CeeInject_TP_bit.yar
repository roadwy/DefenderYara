
rule VirTool_Win32_CeeInject_TP_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 37 5b f8 83 df fc f7 d3 83 eb 23 8d 5b ff 29 d3 89 da 89 1e f8 83 d6 04 83 c1 fc 85 c9 75 e0 } //01 00 
		$a_01_1 = {5e 8d 05 04 10 49 00 ff 30 ff d6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_TP_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {30 04 3e 6a 00 90 09 05 00 e8 90 01 01 ff ff ff 90 00 } //01 00 
		$a_03_1 = {8b c8 0f af 0d 90 01 04 e8 90 01 01 ff ff ff 03 c8 89 0d 90 01 04 e8 90 01 01 ff ff ff 0f b7 15 90 01 04 23 c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_TP_bit_3{
	meta:
		description = "VirTool:Win32/CeeInject.TP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c3 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 83 c4 08 8b d1 8a 12 80 f2 81 88 10 ff 06 41 81 3e 2e 5b 00 00 75 } //01 00 
		$a_03_1 = {55 8b ec 51 81 c2 4a 53 00 00 89 55 fc 8b 7d fc 90 02 10 87 fb ff e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_TP_bit_4{
	meta:
		description = "VirTool:Win32/CeeInject.TP!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 11 8b 0c 24 81 c1 33 f9 03 59 89 4c 24 90 01 01 8b 4c 24 90 01 01 88 14 01 90 00 } //01 00 
		$a_03_1 = {89 54 24 7c 8b 96 90 01 04 8b 9c 24 90 01 01 00 00 00 8b b6 90 01 04 31 fe 81 f3 90 01 04 8b 7c 24 90 01 01 01 c7 90 00 } //01 00 
		$a_03_2 = {89 c8 31 d2 8b 74 24 90 01 01 f7 f6 8b 7c 24 90 01 01 8a 1c 0f 2a 1c 15 90 01 04 8b 54 24 90 01 01 88 1c 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}