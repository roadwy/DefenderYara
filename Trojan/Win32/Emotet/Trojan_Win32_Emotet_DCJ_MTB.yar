
rule Trojan_Win32_Emotet_DCJ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 05 00 "
		
	strings :
		$a_02_0 = {33 d2 8a 11 03 c2 99 b9 90 01 04 f7 f9 90 00 } //05 00 
		$a_00_1 = {8b 45 08 0b 45 0c 8b 4d 08 f7 d1 8b 55 0c f7 d2 0b ca 23 c1 } //03 00 
		$a_81_2 = {41 7a 58 64 53 61 4b 76 62 72 66 67 68 52 54 59 68 } //04 00  AzXdSaKvbrfghRTYh
		$a_81_3 = {45 6d 6f 74 65 74 20 66 6f 72 65 76 65 } //03 00  Emotet foreve
		$a_81_4 = {56 45 4e 45 53 55 45 4c 4c 41 } //05 00  VENESUELLA
		$a_02_5 = {33 d2 8a 11 b9 90 01 04 03 c2 99 f7 f9 90 00 } //05 00 
		$a_02_6 = {0f b6 17 0f b6 06 03 c2 99 b9 90 01 04 f7 f9 68 90 01 04 68 90 00 } //05 00 
		$a_02_7 = {8b 4c 24 04 8b 54 24 08 56 8b c1 8b f2 90 03 0b 0a 0b ca f7 d0 f7 d6 0b c6 5e 23 c1 f7 d0 f7 d6 0b c6 0b ca 23 c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}