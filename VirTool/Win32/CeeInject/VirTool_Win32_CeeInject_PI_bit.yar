
rule VirTool_Win32_CeeInject_PI_bit{
	meta:
		description = "VirTool:Win32/CeeInject.PI!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 90 01 01 03 05 90 01 04 8b fa c1 e7 90 01 01 03 3d 90 01 04 33 c7 8d 3c 16 33 c7 2b c8 8b c1 c1 e8 90 01 01 03 05 90 01 04 8b f9 c1 e7 90 01 01 03 3d 90 01 04 33 c7 8d 3c 0e 2b 75 f8 33 c7 2b d0 ff 4d fc 75 90 00 } //01 00 
		$a_03_1 = {56 57 8b f1 8b f8 56 e8 90 01 01 ff ff ff 83 c6 08 4f 75 f4 90 00 } //01 00 
		$a_03_2 = {56 57 be 20 37 ef c6 e8 90 01 04 89 45 f8 c7 45 fc 20 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}