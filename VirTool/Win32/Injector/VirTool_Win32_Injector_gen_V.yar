
rule VirTool_Win32_Injector_gen_V{
	meta:
		description = "VirTool:Win32/Injector.gen!V,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 8a 4c 0c 14 32 0c 2f 88 0f 8b 8c 24 20 01 00 00 40 3b c1 7c 9e } //01 00 
		$a_03_1 = {68 50 4b 00 00 68 90 01 04 6a 0e 68 90 01 04 68 90 01 04 e8 90 01 04 83 c4 0c 50 e8 90 00 } //01 00 
		$a_03_2 = {02 cb 88 88 90 01 04 8a 0d 90 01 04 02 d1 88 90 90 90 01 04 83 c0 02 3d e0 00 00 00 72 d4 90 00 } //01 00 
		$a_03_3 = {0f af c6 8d 4c 01 01 8d 44 02 01 a3 90 01 04 0f b7 55 06 43 83 c7 28 3b da 7c 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}