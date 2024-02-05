
rule VirTool_Win32_Obfuscator_KH{
	meta:
		description = "VirTool:Win32/Obfuscator.KH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 51 8b 4d 0c 33 d2 f7 f1 59 4e 8a 06 86 04 3a 88 06 58 49 0b c9 75 e3 } //01 00 
		$a_03_1 = {03 5b 3c 8b 4b 54 81 c3 f8 00 00 00 90 03 03 04 8b 5b 14 ff 73 14 90 02 05 5b 0b db 75 02 90 00 } //01 00 
		$a_03_2 = {68 c8 12 11 97 50 e8 90 01 04 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}