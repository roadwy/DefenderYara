
rule VirTool_Win32_CeeInject_TQ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 43 01 be 90 01 04 33 d2 f7 f6 8b c1 03 c3 88 10 43 81 fb 90 01 04 75 90 00 } //01 00 
		$a_03_1 = {03 c3 8a 00 90 02 10 34 dc 8b 15 90 01 04 03 d3 88 02 90 02 10 43 81 fb 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_TQ_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 f3 88 dd 88 4c 24 90 01 01 88 e9 8b 5c 24 90 01 01 d3 e3 89 5c 24 90 01 01 8a 4c 24 90 01 01 88 0a 8b 54 24 90 01 01 81 c2 90 01 04 8b 5c 24 90 01 01 83 d3 00 8b 7c 24 90 01 01 01 c7 90 00 } //01 00 
		$a_03_1 = {8a 1c 11 8a bc 02 90 01 04 28 fb 8b 44 24 90 01 01 88 1c 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_TQ_bit_3{
	meta:
		description = "VirTool:Win32/CeeInject.TQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 7e 08 89 56 04 c7 46 0c 04 00 00 00 c7 06 00 00 00 00 ff d0 } //01 00 
		$a_03_1 = {8b 44 24 50 8a 1c 15 90 01 04 35 90 01 04 8b 54 24 90 01 01 8a 3c 0a 8b 74 24 90 01 01 8b 7c 24 90 01 01 29 fe 28 df 89 74 24 90 01 01 8b 74 24 90 01 01 88 3c 0e 01 c1 90 00 } //01 00 
		$a_03_2 = {eb 00 8b 44 24 90 01 01 8b 4c 24 90 01 01 81 c1 90 01 04 8a 10 89 4c 24 90 01 01 8b 44 24 90 01 01 8b 4c 24 90 01 01 88 14 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}