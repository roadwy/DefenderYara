
rule VirTool_Win32_Obfuscator_MZ{
	meta:
		description = "VirTool:Win32/Obfuscator.MZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 b9 99 99 99 99 50 58 2d 00 01 00 00 05 00 01 00 00 e2 f2 } //01 00 
		$a_01_1 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 50 8b c3 33 c0 58 cc } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_MZ_2{
	meta:
		description = "VirTool:Win32/Obfuscator.MZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d c8 8b 45 fc 03 40 3c 8b 40 28 03 45 fc 5b c9 8b f4 83 c6 10 68 00 40 00 00 68 00 10 00 00 51 50 52 c3 } //01 00 
		$a_01_1 = {c1 c7 07 83 c7 02 03 f8 80 3e 00 75 f2 } //00 00 
	condition:
		any of ($a_*)
 
}