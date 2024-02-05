
rule VirTool_Win32_Injector_gen_EN{
	meta:
		description = "VirTool:Win32/Injector.gen!EN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 00 30 00 00 2b 8d 90 01 04 89 4d f8 8d 55 f8 89 95 90 01 04 b8 40 00 00 00 2b 85 90 01 04 89 85 90 01 04 90 02 40 8b 51 50 89 95 90 01 04 8b 85 90 01 04 8b 48 34 89 8d 90 00 } //01 00 
		$a_03_1 = {0f b7 51 06 39 95 90 01 04 0f 8d 90 01 04 8b 85 90 01 04 8b 48 3c 03 8d 90 01 04 8b 55 fc 8b 85 90 01 04 0f af 02 03 c8 90 00 } //01 00 
		$a_03_2 = {03 42 28 8b 8d 90 01 04 89 81 b0 00 00 00 90 00 } //01 00 
		$a_01_3 = {c7 01 07 00 01 00 } //01 00 
	condition:
		any of ($a_*)
 
}