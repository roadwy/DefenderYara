
rule VirTool_Win32_Injector_gen_DL{
	meta:
		description = "VirTool:Win32/Injector.gen!DL,SIGNATURE_TYPE_PEHSTR_EXT,64 00 07 00 0e 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c9 83 f8 0d 0f 9e c1 f7 d9 8b f1 8d 4d } //01 00 
		$a_01_1 = {c7 45 e7 47 50 41 00 } //01 00 
		$a_01_2 = {66 83 c1 03 } //01 00 
		$a_01_3 = {b8 fc fd fe ff } //01 00 
		$a_01_4 = {2d 04 04 04 04 } //01 00 
		$a_01_5 = {0f b7 47 14 } //01 00 
		$a_01_6 = {66 3b 77 06 } //01 00  㭦ٷ
		$a_01_7 = {bb 00 00 40 00 } //01 00 
		$a_01_8 = {03 5f 28 eb } //01 00 
		$a_01_9 = {6b c6 28 eb } //01 00 
		$a_01_10 = {64 a1 30 00 00 00 92 8b 52 0c 8b 52 14 } //01 00 
		$a_01_11 = {83 f8 10 7f 07 6a 00 e8 } //01 00 
		$a_01_12 = {ff 77 54 eb } //01 00 
		$a_01_13 = {8b 50 78 eb } //01 00 
	condition:
		any of ($a_*)
 
}