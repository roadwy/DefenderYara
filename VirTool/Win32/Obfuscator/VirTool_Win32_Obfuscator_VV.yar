
rule VirTool_Win32_Obfuscator_VV{
	meta:
		description = "VirTool:Win32/Obfuscator.VV,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 67 6f 78 75 5c 65 72 61 6c 79 67 61 2e 70 64 62 } //01 00 
		$a_01_1 = {58 75 62 69 71 79 7a 5c 59 6c 61 6d 65 2e 70 64 62 } //01 00 
		$a_01_2 = {4e 69 7a 65 6c 5c 6f 68 75 77 61 68 2e 70 64 62 } //01 00 
		$a_01_3 = {4e 69 6b 6f 62 5c 4b 65 78 61 2e 70 64 62 } //01 00 
		$a_00_4 = {89 4d e0 81 7d e0 64 8b 02 00 7d 3b } //01 00 
		$a_00_5 = {89 4d e4 81 7d e4 46 89 02 00 7d 27 } //01 00 
		$a_00_6 = {89 55 e0 81 7d e0 40 8d 02 00 7d 3a } //01 00 
		$a_00_7 = {89 45 e8 81 7d e8 fa 8f 02 00 7d 3c } //00 00 
	condition:
		any of ($a_*)
 
}