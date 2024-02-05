
rule VirTool_Win32_CeeInject_TL_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TL!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {85 d2 75 09 8b 45 90 01 01 83 c0 03 89 45 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 8b 55 90 01 01 8a 82 90 01 03 00 88 01 eb b6 90 00 } //01 00 
		$a_03_1 = {00 00 73 13 8b 55 90 01 01 03 55 90 01 01 8b 45 90 01 01 8a 88 90 01 03 00 88 0a eb db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_TL_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TL!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c7 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 } //01 00 
		$a_03_1 = {8a 00 50 8b c6 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 71 90 01 01 e8 90 01 04 83 c4 08 5a 88 10 90 00 } //01 00 
		$a_03_2 = {8b c3 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 71 05 e8 90 01 04 83 c4 08 32 0d 90 01 04 88 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}