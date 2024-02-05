
rule VirTool_Win32_CeeInject_SU_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SU!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4e 08 b8 90 01 04 8b 1e 2b cb f7 e9 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 c2 3d 90 00 } //01 00 
		$a_03_1 = {8b c1 c1 e8 90 01 01 30 04 1a 42 3b 55 10 7c 90 09 0c 00 69 c9 90 01 04 81 c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_SU_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.SU!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 8b 45 fc e8 90 01 04 50 6a 00 ff 15 90 00 } //01 00 
		$a_03_1 = {8b e8 8d b5 90 01 04 4e 83 c6 04 81 e6 90 01 04 6a 04 68 90 01 04 56 6a 00 e8 90 01 04 8b d8 85 db 90 00 } //01 00 
		$a_03_2 = {8b de 66 81 3b 4d 5a 0f 85 90 01 04 8b c6 33 d2 52 50 8b 43 3c 99 03 04 24 13 54 24 04 83 c4 08 8b f8 81 3f 50 45 00 00 0f 85 90 00 } //01 00 
		$a_03_3 = {50 8b 47 50 50 56 8b 45 90 01 01 50 8b 45 90 01 01 50 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}