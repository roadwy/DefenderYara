
rule VirTool_Win32_Injector_gen_FE{
	meta:
		description = "VirTool:Win32/Injector.gen!FE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 30 00 00 68 00 10 00 00 57 90 18 ff 53 90 00 } //01 00 
		$a_03_1 = {c7 00 07 00 01 00 ff 75 90 01 01 89 45 90 00 } //01 00 
		$a_01_2 = {51 51 89 45 f8 33 c0 50 68 00 00 00 08 6a 40 8d 4d f8 } //01 00 
		$a_01_3 = {68 1f 00 0f 00 ff 75 0c 89 45 fc 8b 45 08 ff 50 } //01 00 
		$a_03_4 = {8b 45 d8 03 4d cc 90 18 50 89 88 b0 00 00 00 ff 75 e4 90 00 } //01 00 
		$a_01_5 = {8b 46 34 8b 7e 50 57 } //01 00 
		$a_03_6 = {0f b7 46 06 ff 45 fc 59 90 18 83 c7 28 59 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}