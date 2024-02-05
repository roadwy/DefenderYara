
rule VirTool_Win32_Obfuscator_FO{
	meta:
		description = "VirTool:Win32/Obfuscator.FO,SIGNATURE_TYPE_PEHSTR_EXT,08 00 02 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 6e 0f b7 10 81 fa 4d 5a 00 00 75 63 03 40 3c 8b 08 81 f9 50 45 00 00 75 56 8b 50 74 8d 40 78 8d 04 d0 } //02 00 
		$a_03_1 = {59 49 e3 02 eb 90 01 01 53 30 14 24 30 54 24 01 30 54 24 02 30 54 24 03 90 00 } //01 00 
		$a_03_2 = {75 16 8b 42 28 01 c6 8b 3d 90 01 04 29 f7 83 ef 05 c6 06 e9 89 7e 01 90 00 } //01 00 
		$a_03_3 = {8d 14 02 8a 02 32 05 90 01 04 88 02 ff 45 fc e2 e6 90 00 } //01 00 
		$a_01_4 = {8b 78 04 81 3b 03 00 00 80 74 07 b8 00 00 00 00 eb 0b ff 87 b8 00 00 00 b8 ff ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}