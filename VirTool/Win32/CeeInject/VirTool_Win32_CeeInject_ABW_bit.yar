
rule VirTool_Win32_CeeInject_ABW_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABW!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 14 0e 80 f2 1a 88 11 41 4f 75 d8 90 09 1c 00 8b 15 90 01 04 0f af 15 90 01 04 39 15 90 01 04 7d 07 90 00 } //01 00 
		$a_03_1 = {51 50 ff 54 24 90 01 01 6a 40 68 90 01 04 68 90 01 04 6a 00 ff d0 be 90 01 04 8b c8 2b f0 90 00 } //01 00 
		$a_03_2 = {85 c0 8b 2d 90 01 04 0f 84 90 01 04 8b 15 90 01 04 0f bf 3d 90 01 04 8b c6 33 c2 89 44 24 90 01 01 0f bf 05 90 01 04 0f af c6 33 fe 8b 35 90 01 04 89 44 24 90 01 01 89 7c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}