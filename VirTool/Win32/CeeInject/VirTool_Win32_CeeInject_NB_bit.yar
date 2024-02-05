
rule VirTool_Win32_CeeInject_NB_bit{
	meta:
		description = "VirTool:Win32/CeeInject.NB!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 85 a4 df ff ff 25 ff 90 00 90 8b 4d fc 33 d2 8a 94 0d b4 d2 ff ff 33 c2 8b 4d fc } //01 00 
		$a_03_1 = {70 f8 27 41 6a 90 01 01 8d 95 d4 df ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_NB_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.NB!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b cf c1 e9 90 01 01 03 4c 24 90 01 01 8b d7 c1 e2 90 01 01 03 54 24 90 01 01 8d 04 3b 33 ca 33 c8 6a 00 2b f1 ff 15 90 01 04 8b ce c1 e9 90 01 01 03 4c 24 90 01 01 8b d6 c1 e2 90 01 01 03 54 24 90 01 01 8d 04 33 33 ca 33 c8 2b f9 81 c3 90 01 04 83 ed 01 75 90 00 } //01 00 
		$a_03_1 = {8a 14 06 88 10 8b 55 90 01 01 41 40 3b ca 72 f2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}