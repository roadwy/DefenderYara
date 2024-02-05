
rule VirTool_Win32_CeeInject_TT_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TT!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 04 39 49 75 fa } //01 00 
		$a_03_1 = {6a 00 89 0c 90 01 01 33 c9 03 c8 8b f9 59 6a 00 89 04 90 01 01 33 c0 03 c7 89 83 90 01 04 58 6a 00 89 04 90 01 01 2b c0 0b 83 90 01 04 8b f0 58 6a 00 89 3c 90 01 01 33 ff 0b bb 90 01 04 8b cf 5f f3 a4 90 00 } //01 00 
		$a_01_2 = {52 59 03 cb 8b d1 59 23 d9 55 8b e8 33 eb 8b c5 5d ff e0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_TT_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TT!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 99 f7 ff 0f b6 9a 90 01 04 c1 e3 1b 8b d1 c1 e2 18 33 da c1 eb 18 88 1c 31 41 81 f9 90 01 04 72 90 00 } //01 00 
		$a_01_1 = {f7 e9 8b d9 c1 fb 1f 03 d1 c1 fa 09 2b d3 69 d2 ef 02 00 00 f7 da 03 d1 0f b6 1c 32 30 1f 47 41 } //01 00 
		$a_03_2 = {f7 e9 8b f1 c1 fe 1f c1 fa 08 2b d6 69 d2 9a 04 00 00 47 f7 da 8b 74 24 90 01 01 03 d1 0f b6 14 32 41 30 13 43 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}