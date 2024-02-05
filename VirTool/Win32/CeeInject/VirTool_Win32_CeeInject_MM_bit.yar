
rule VirTool_Win32_CeeInject_MM_bit{
	meta:
		description = "VirTool:Win32/CeeInject.MM!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 68 93 03 00 6a 00 ff d0 a3 } //01 00 
		$a_03_1 = {8b 06 83 c6 04 33 05 90 01 04 03 05 90 01 04 03 05 90 01 04 c1 c0 90 01 01 c1 c0 90 01 01 ab 81 fe 90 01 04 7e da ff 35 90 01 04 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_MM_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.MM!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 85 a4 df ff ff 25 ff 90 00 90 8b 4d fc 33 d2 8b 94 0d b4 d2 ff ff 33 c2 8b 4d fc 87 84 0d ac df ff ff 8b 55 fc 33 c0 8a 84 15 ac df ff ff 83 f8 3a 7f 19 8b 4d fc 33 d2 8a 94 0d ac df ff ff 83 ea 01 8b 45 fc } //01 00 
		$a_01_1 = {70 f8 27 41 6a 90 8d 95 d4 df ff ff ff d2 } //00 00 
	condition:
		any of ($a_*)
 
}