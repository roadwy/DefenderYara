
rule VirTool_Win32_VBInject_gen_LG{
	meta:
		description = "VirTool:Win32/VBInject.gen!LG,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 a1 18 00 00 00 8b 40 30 80 78 02 01 } //01 00 
		$a_01_1 = {64 8b 1d 18 00 00 00 8b 5b 30 80 7b 02 01 } //01 00 
		$a_03_2 = {64 8b 0d 18 00 00 00 90 02 01 8b 49 30 90 02 01 80 79 02 01 90 00 } //01 00 
		$a_03_3 = {0f 6e c8 0f 6e c2 90 02 04 0f f8 c8 0f d7 d8 0f 77 01 de 01 d9 81 f9 90 00 } //01 00 
		$a_01_4 = {0f f8 c8 0f 64 c1 0f d7 d8 01 d9 81 f9 } //01 00 
		$a_03_5 = {83 c1 02 83 e9 02 41 83 c6 02 83 ee 02 46 81 f9 90 01 04 72 ea 81 fe 90 00 } //01 00 
		$a_01_6 = {0f 31 25 ff 00 00 00 01 c6 81 fe b0 ab 5f 0d 72 ee } //01 00 
		$a_01_7 = {0f 6e 07 0f 6e ce 0f ef c1 0f 7e 07 } //0c 00 
		$a_03_8 = {81 38 55 8b ec 83 90 02 01 75 90 02 02 81 78 04 ec 0c 56 8d 90 00 } //0c 00 
		$a_03_9 = {81 78 04 ec 0c 56 8d 90 02 01 75 90 02 02 81 38 55 8b ec 83 90 00 } //00 00 
		$a_00_10 = {80 10 00 00 00 5e 05 68 64 85 a3 d2 d1 } //08 e3 
	condition:
		any of ($a_*)
 
}