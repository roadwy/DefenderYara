
rule VirTool_Win32_Injector_HO{
	meta:
		description = "VirTool:Win32/Injector.HO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 10 4e 75 1a 51 8b ce 8b 01 8b c8 58 33 ca } //01 00 
		$a_01_1 = {8a d5 40 88 10 8b f8 59 46 59 5a 4a 85 d2 74 db e2 bd } //01 00 
		$a_03_2 = {58 5e 8b f8 8d 0d 90 01 04 ff 36 57 ff d1 c3 90 00 } //01 00 
		$a_01_3 = {80 79 44 00 75 0c 80 b9 88 00 00 00 00 75 03 33 c0 e8 } //01 00 
		$a_00_4 = {87 10 } //00 00 
	condition:
		any of ($a_*)
 
}