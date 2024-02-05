
rule VirTool_Win32_Injector_EQ{
	meta:
		description = "VirTool:Win32/Injector.EQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 5a e4 3e c0 e8 90 01 04 90 03 02 01 ff d0 e9 90 00 } //01 00 
		$a_03_1 = {68 5a e4 3e c0 90 03 01 02 e9 60 e9 90 00 } //01 00 
		$a_03_2 = {68 0a ed dc e7 e8 90 01 04 90 03 02 01 ff d0 e9 90 00 } //01 00 
		$a_01_3 = {68 0a ed dc e7 e9 } //01 00 
		$a_03_4 = {32 04 13 aa 42 90 03 01 03 e9 3b 55 0c 90 00 } //01 00 
		$a_03_5 = {32 04 13 e9 90 01 02 90 03 02 02 00 00 ff ff 90 00 } //01 00 
		$a_01_6 = {32 04 13 aa e9 } //00 00 
		$a_00_7 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}