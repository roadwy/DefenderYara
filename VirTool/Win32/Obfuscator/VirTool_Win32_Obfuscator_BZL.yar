
rule VirTool_Win32_Obfuscator_BZL{
	meta:
		description = "VirTool:Win32/Obfuscator.BZL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c2 5a 47 5a 88 27 46 4a 8b c2 85 c0 75 07 8b 55 14 8b 75 10 4e e2 } //01 00 
		$a_01_1 = {8d 78 18 b9 0a 00 00 00 f3 8b 06 52 8b 17 52 85 c9 75 2e a5 } //01 00 
		$a_01_2 = {5f 5e 8b 06 50 57 ff d1 } //01 00 
		$a_03_3 = {89 07 58 47 48 47 47 47 90 03 03 03 ab 6a 04 6a 04 ab 5a 8b 06 90 03 06 06 03 f2 89 07 03 fa 89 07 03 fa 03 f2 49 75 f5 90 00 } //01 00 
		$a_00_4 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}