
rule Trojan_Win32_Tapaoux_B{
	meta:
		description = "Trojan:Win32/Tapaoux.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c7 8a 0e 99 f7 7c 24 10 8a 54 14 14 3a ca 74 02 32 ca 88 0c 33 47 46 3b fd 7c e4 } //01 00 
		$a_01_1 = {8b c7 99 f7 7c 24 10 8b c1 25 ff 00 00 00 8a 54 14 14 0f be ea 3b c5 74 02 32 ca } //01 00 
		$a_03_2 = {8b 6f 3c 03 ef 8b 90 01 01 50 8b 90 01 01 34 90 00 } //01 00 
		$a_01_3 = {68 1a 4c 72 0a 12 0b 48 04 25 19 5c 1b 0b 4e 4a } //01 00  ᩨ牌ሊ䠋┄尙ଛ䩎
		$a_01_4 = {3d 69 0d 15 4f 41 41 54 5a 7c 47 51 47 5a 53 42 } //01 00  椽ᔍ䅏呁籚兇婇䉓
		$a_01_5 = {54 b8 11 11 11 11 ff d0 90 90 90 90 } //00 00 
	condition:
		any of ($a_*)
 
}