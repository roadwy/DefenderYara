
rule VirTool_Win32_CeeInject_UL_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UL!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 9e 90 01 04 8b c6 f7 f5 0f be 04 0a 03 c7 0f b6 cb 03 c8 0f b6 f9 8b 4c 24 90 01 01 89 3d 90 01 04 8a 87 90 01 04 88 86 90 01 04 46 88 9f 90 01 04 89 35 90 01 04 81 fe 90 01 04 75 bb 90 00 } //01 00 
		$a_03_1 = {8b 4c 24 0c 8b d0 e8 90 01 04 eb 08 e8 90 01 04 30 04 37 83 ee 01 79 f3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_UL_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.UL!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 8a 45 10 88 45 90 01 01 8b 4d 08 03 4d 0c 8a 55 90 01 01 88 11 8b e5 5d 90 00 } //01 00 
		$a_01_1 = {55 8b ec 8b 45 08 03 45 0c 8b 4d 10 8a 10 88 11 5d } //01 00 
		$a_03_2 = {2b d8 88 5d 90 09 08 00 8b 54 85 90 01 01 8d 44 16 90 00 } //01 00 
		$a_03_3 = {51 6a 00 6a 00 68 90 01 04 ff 15 90 01 04 50 ff 15 90 01 04 89 45 90 01 01 8b 5d 90 01 01 ff 75 90 01 01 ff 75 90 01 01 68 90 01 04 6a 00 6a ff 5a ff d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}