
rule VirTool_Win32_Obfuscator_ALO{
	meta:
		description = "VirTool:Win32/Obfuscator.ALO,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 48 01 33 4b 08 51 33 c9 8a 0c 02 5f 2b cf 88 0c 02 8d 48 01 33 4b 04 51 33 c9 8a 0c 02 5f 2b cf 88 0c 02 8d 48 01 33 0b 51 33 c9 8a 0c 02 5f 2b cf 88 0c 02 40 } //01 00 
		$a_03_1 = {e8 00 00 00 00 58 89 45 90 01 01 c6 45 90 01 01 42 c6 45 90 01 01 21 c6 45 90 01 01 33 33 c0 40 8b 55 90 01 01 03 d0 4a 8a 12 3a 55 90 01 01 75 f2 90 00 } //01 00 
		$a_03_2 = {03 d0 c6 45 90 01 01 47 c6 45 90 01 01 41 c6 45 90 01 01 50 8b 42 90 01 01 48 83 f8 00 72 5f 8b 72 90 01 01 03 37 8b c8 c1 e1 02 03 f1 8b 4e 90 01 01 03 0f 8a 49 03 3a 4d 90 01 01 75 40 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}