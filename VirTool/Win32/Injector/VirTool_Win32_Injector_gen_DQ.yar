
rule VirTool_Win32_Injector_gen_DQ{
	meta:
		description = "VirTool:Win32/Injector.gen!DQ,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 f8 10 77 07 b8 03 00 00 00 ff e0 fc } //01 00 
		$a_01_1 = {81 f9 00 01 00 00 } //01 00 
		$a_01_2 = {66 83 c1 03 } //01 00 
		$a_01_3 = {0f b7 47 14 } //01 00 
		$a_01_4 = {bb 00 00 40 00 } //01 00 
		$a_01_5 = {66 3b 77 06 } //01 00  㭦ٷ
		$a_03_6 = {56 8b 0e fc 90 02 0f 64 8b 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}