
rule VirTool_Win32_Obfuscator_QG{
	meta:
		description = "VirTool:Win32/Obfuscator.QG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 54 3e ff 09 e9 } //01 00 
		$a_01_1 = {3d f0 35 05 00 e9 } //01 00 
		$a_01_2 = {68 20 10 dc ba e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_QG_2{
	meta:
		description = "VirTool:Win32/Obfuscator.QG,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_11_0 = {8d 59 41 13 e9 01 } //00 06 
		$a_68_1 = {e2 26 6d e9 01 00 04 11 8b 42 18 e9 01 00 04 11 0f } //b7 0c 
		$a_01_2 = {00 04 11 8b 04 88 e9 00 00 78 4e 00 00 04 00 03 00 03 00 00 01 00 14 01 fe 57 e7 67 5e 12 12 aa a3 17 13 0e e8 39 17 f7 57 1c 1c d2 01 00 14 01 25 5e e8 86 39 53 0c 1e e7 15 f5 72 31 53 22 2b 15 13 4a 78 01 00 11 01 } //e4 96 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_QG_3{
	meta:
		description = "VirTool:Win32/Obfuscator.QG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {fe 57 e7 67 5e 12 12 aa a3 17 13 0e e8 39 17 f7 57 1c 1c d2 } //01 00 
		$a_01_1 = {25 5e e8 86 39 53 0c 1e e7 15 f5 72 31 53 22 2b 15 13 4a 78 } //01 00 
		$a_01_2 = {e4 96 78 33 15 3a 27 15 1a b2 fe 07 15 0e 06 3d 33 } //00 00 
	condition:
		any of ($a_*)
 
}