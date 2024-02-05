
rule VirTool_Win32_CeeInject_SV_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SV!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 11 8b 45 fc 03 45 90 01 01 0f b6 08 8d 54 11 02 8b 45 fc 03 45 90 01 01 88 10 8b 4d fc 03 4d 90 01 01 0f b6 11 83 ea 02 8b 45 fc 03 45 90 01 01 88 10 c7 45 f0 90 01 03 00 8b 4d f8 83 c1 01 89 4d f8 e9 43 ff ff ff 90 00 } //01 00 
		$a_01_1 = {8b 55 08 8b 02 03 45 fc 8b 4d 08 89 01 8b e5 5d c3 } //01 00 
		$a_03_2 = {8b ca 33 c1 90 02 30 89 11 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_SV_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.SV!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {ff ff ff 24 03 00 00 73 52 8b 90 01 02 ff ff ff 8b 90 01 04 41 00 89 90 01 02 ff ff ff 8b 90 01 02 ff ff ff 2b 90 01 02 ff ff ff 89 90 01 02 ff ff ff c1 85 90 01 01 ff ff ff 0f 8b 90 01 02 ff ff ff 33 90 01 03 41 00 89 90 01 02 ff ff ff 8b 90 01 02 ff ff ff 8b 90 01 02 8b 90 01 02 ff ff ff 89 90 01 02 eb 93 90 00 } //02 00 
		$a_03_1 = {24 03 00 00 73 33 8b 45 90 01 01 8b 4d 90 01 01 8b 14 81 89 55 90 01 01 8b 45 90 01 01 2b 45 90 01 01 89 45 90 01 01 c1 45 90 01 01 0f 8b 4d 90 01 01 33 0d 90 01 04 89 4d 90 01 01 8b 55 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 89 0c 90 90 eb bb 90 00 } //01 00 
		$a_01_2 = {68 b8 88 00 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}