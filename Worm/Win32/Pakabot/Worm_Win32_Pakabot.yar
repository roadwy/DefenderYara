
rule Worm_Win32_Pakabot{
	meta:
		description = "Worm:Win32/Pakabot,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0d 00 00 03 00 "
		
	strings :
		$a_01_0 = {68 65 68 20 68 65 68 20 68 65 68 20 3a 6b 61 6b 61 70 } //01 00  heh heh heh :kakap
		$a_01_1 = {68 02 20 00 00 ff 15 } //02 00 
		$a_01_2 = {6a 00 6a 01 6a 00 6a 11 ff } //01 00 
		$a_01_3 = {6a 00 6a 00 6a 00 6a 0d ff } //02 00 
		$a_01_4 = {41 2d 9e 24 dd 44 64 4d 9b 6b d5 fd 76 } //02 00 
		$a_01_5 = {6a 00 6a 03 6a 2d 6a 11 ff } //01 00 
		$a_01_6 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //01 00  SetClipboardData
		$a_03_7 = {6a 00 6a 00 6a 00 6a ff ff 15 90 01 04 85 c0 74 90 00 } //05 00 
		$a_01_8 = {8b 55 08 03 55 fc 8a 02 32 45 0c 8b 4d 08 03 4d fc 88 01 eb } //05 00 
		$a_01_9 = {83 3d 40 01 80 7c 00 75 } //05 00 
		$a_01_10 = {a1 40 01 80 7c 85 c0 75 } //06 00 
		$a_03_11 = {6a 0a ff 15 90 01 04 ff 15 90 01 04 89 85 90 01 02 ff ff 6a 0a ff 15 90 01 04 ff 15 90 01 04 89 85 90 01 02 ff ff 8b 85 90 01 02 ff ff 2b 90 03 04 06 45 90 01 01 85 90 01 02 ff ff 83 f8 0a 73 90 01 01 8b 8d 90 01 02 ff ff 2b 90 03 04 06 4d 90 01 01 8d 90 01 02 ff ff 83 f9 14 73 90 00 } //06 00 
		$a_03_12 = {6a 0a 8b d8 ff d5 ff d7 6a 0a 8b f0 ff d5 ff d7 2b f3 5d 83 fe 0a 73 90 01 01 2b c3 83 f8 14 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}