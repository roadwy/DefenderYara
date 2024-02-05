
rule TrojanDropper_Win32_Sirefef_F{
	meta:
		description = "TrojanDropper:Win32/Sirefef.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 0a 8b 48 08 8b 40 0c 2b c8 f7 d9 1b c9 81 e1 03 00 00 40 89 06 8b c1 eb d4 } //01 00 
		$a_01_1 = {8a 10 6b db 21 88 55 0b 0f be d2 33 da 40 80 7d 0b 00 75 ec } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_Win32_Sirefef_F_2{
	meta:
		description = "TrojanDropper:Win32/Sirefef.F,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 0a 8b 48 08 8b 40 0c 2b c8 f7 d9 1b c9 81 e1 03 00 00 40 89 06 8b c1 eb d4 } //01 00 
		$a_01_1 = {8a 10 6b db 21 88 55 0b 0f be d2 33 da 40 80 7d 0b 00 75 ec } //00 00 
	condition:
		any of ($a_*)
 
}