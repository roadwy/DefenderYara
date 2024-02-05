
rule VirTool_Win32_Injector_gen_CV{
	meta:
		description = "VirTool:Win32/Injector.gen!CV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 00 cf 00 68 90 01 04 68 90 01 04 68 00 03 00 00 e8 90 01 04 a3 90 01 04 68 58 02 00 00 ff 75 08 e8 90 00 } //01 00 
		$a_01_1 = {47 65 6e 65 72 69 63 5f 43 6c 61 73 73 00 } //01 00 
		$a_01_2 = {41 73 73 65 6d 62 6c 65 72 2c 20 50 75 72 65 20 26 20 53 69 6d 70 6c 65 00 } //01 00 
		$a_03_3 = {8d 45 fc eb 90 14 eb 90 14 90 03 01 01 eb e9 90 00 } //01 00 
		$a_00_4 = {5d 04 00 } //00 ab 
	condition:
		any of ($a_*)
 
}