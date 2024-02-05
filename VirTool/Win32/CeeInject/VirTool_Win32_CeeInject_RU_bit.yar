
rule VirTool_Win32_CeeInject_RU_bit{
	meta:
		description = "VirTool:Win32/CeeInject.RU!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 b8 00 00 10 00 50 e8 90 01 04 90 03 02 03 85 c0 83 f8 00 0f 85 90 01 04 68 90 01 04 b8 00 00 00 00 50 b8 00 00 10 00 50 e8 90 01 04 90 03 02 03 85 c0 83 f8 00 0f 85 90 01 04 68 90 01 04 b8 00 00 00 00 50 b8 00 00 10 00 50 e8 90 01 04 90 03 02 03 85 c0 83 f8 00 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_RU_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.RU!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 52 8b 85 90 01 04 8b 0c 85 90 01 04 89 8d 90 01 04 8b 95 90 01 04 2b 95 90 01 04 89 95 90 01 04 c1 85 90 01 04 0f 8b 85 90 01 04 33 05 90 01 04 89 85 90 01 04 8b 8d 90 01 04 8b 55 90 01 01 8b 85 90 01 04 89 04 8a eb 93 90 00 } //01 00 
		$a_03_1 = {c1 e1 06 51 8b 15 90 01 04 52 a1 90 01 04 50 6a 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}