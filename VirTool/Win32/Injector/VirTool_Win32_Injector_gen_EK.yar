
rule VirTool_Win32_Injector_gen_EK{
	meta:
		description = "VirTool:Win32/Injector.gen!EK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {f7 d8 05 00 30 00 00 89 85 90 01 04 90 02 20 f7 d8 83 c0 40 89 85 90 01 04 90 02 40 8b 85 90 01 04 8b 40 50 89 85 90 01 04 8b 85 90 01 04 8b 40 34 89 85 90 00 } //01 00 
		$a_03_1 = {0f b7 52 06 0f b7 d2 3b c2 0f 8d 90 01 04 8b 85 90 01 04 8b 95 90 01 04 03 50 3c 8b 85 90 01 04 8b 00 0f af 85 90 01 04 03 d0 89 95 90 00 } //01 00 
		$a_03_2 = {8b 40 28 03 85 90 01 04 8b 95 90 01 04 89 82 b0 00 00 00 90 00 } //01 00 
		$a_01_3 = {c7 00 07 00 01 00 } //01 00 
	condition:
		any of ($a_*)
 
}