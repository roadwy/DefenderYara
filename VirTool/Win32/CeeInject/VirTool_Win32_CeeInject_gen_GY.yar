
rule VirTool_Win32_CeeInject_gen_GY{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 56 50 8b 46 34 8b 8d 90 01 04 6a 40 68 00 30 00 00 52 50 51 ff 95 90 00 } //01 00 
		$a_03_1 = {8d 84 38 f8 00 00 00 8b 40 0c 03 46 34 6a 00 51 8b 8d 90 01 04 03 d7 52 50 51 ff 95 90 01 04 0f b7 56 06 83 85 90 01 04 28 90 00 } //01 00 
		$a_01_2 = {8d 4d 08 8a 55 24 30 14 01 8b 4d 08 39 5d 1c 73 03 8d 4d 08 8a 55 28 30 14 01 8b 4d 08 39 5d 1c 73 03 8d 4d 08 8a 55 2c 30 14 01 40 3b 45 18 72 c7 } //01 00 
	condition:
		any of ($a_*)
 
}