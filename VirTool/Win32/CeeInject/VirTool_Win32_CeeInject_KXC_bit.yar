
rule VirTool_Win32_CeeInject_KXC_bit{
	meta:
		description = "VirTool:Win32/CeeInject.KXC!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 4c 37 03 8a c1 8a d9 80 e1 f0 24 fc 02 c9 c0 e0 04 0a 44 37 01 c0 e3 06 0a 5c 37 02 02 c9 0a 0c 37 8b 7d fc 88 0c 3a 42 88 04 3a 42 88 1c 3a 83 c6 04 42 3b 35 } //01 00 
		$a_03_1 = {53 56 57 68 90 01 04 ff 15 90 01 04 8b 3d 90 01 04 8b f0 a3 90 01 04 b0 90 01 01 88 44 24 90 01 01 88 44 24 90 01 01 8d 44 24 90 01 01 b2 90 01 01 b3 90 01 01 b1 90 01 01 50 56 90 00 } //01 00 
		$a_03_2 = {53 56 57 68 90 01 04 ff 15 90 01 04 8b 3d 90 01 04 8b f0 a3 90 01 04 b0 90 01 01 88 84 24 90 01 04 88 84 24 90 01 04 8d 84 24 90 01 04 b2 90 01 01 b1 90 01 01 b3 90 01 01 50 56 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}