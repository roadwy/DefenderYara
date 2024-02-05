
rule VirTool_Win32_CeeInject_TV_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TV!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c7 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 83 c4 08 8a 00 32 05 90 01 04 50 8b c6 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 83 c4 08 5a 88 10 41 4b 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_TV_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TV!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 90 01 01 0f b6 08 0f b6 55 90 01 01 33 ca 8b 45 90 01 01 88 8c 05 90 01 04 8b 4d 90 01 01 83 c1 01 89 4d 90 01 01 0f b6 4d 90 01 01 8b 45 90 01 01 99 be 85 00 00 00 f7 fe 6b d2 03 03 ca 81 e1 ff 00 00 00 88 4d 90 00 } //01 00 
		$a_03_1 = {c1 e2 05 b8 01 00 00 00 6b c8 00 0f be 94 0a 90 01 04 85 d2 74 1f 8b 45 90 01 01 c1 e0 05 05 90 01 04 50 8b 4d 90 01 01 83 c1 01 c1 e1 05 03 4d 90 01 01 51 ff 15 90 00 } //01 00 
		$a_03_2 = {7d 2d 6b 45 90 01 01 28 8b 4d 90 01 01 6b 55 90 01 01 28 8b 75 90 01 01 8b 5d 08 03 5c 16 14 6b 55 90 01 01 28 8b 75 90 01 01 8b 7d 90 01 01 03 7c 16 0c 8b f3 8b 4c 01 10 f3 a4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}