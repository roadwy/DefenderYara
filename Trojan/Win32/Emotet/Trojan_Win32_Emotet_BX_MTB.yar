
rule Trojan_Win32_Emotet_BX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2b c2 d1 f8 8b c8 8b c7 33 d2 f7 f1 47 8a 44 55 00 30 44 1f ff 3b 7c 24 1c 0f 85 } //01 00 
		$a_00_1 = {33 d2 8b c8 8b 45 fc f7 f1 8b 45 08 8a 04 50 30 03 ff 45 fc 8b 45 fc 3b 45 10 75 } //01 00 
		$a_00_2 = {8b c8 8b 45 fc 33 d2 f7 f1 8b 45 08 8a 04 50 30 03 ff 45 fc 8b 45 fc 3b 45 10 } //01 00 
		$a_02_3 = {8b c8 33 d2 8b c5 f7 f1 8b 44 24 14 8a 04 50 30 03 45 81 fd 90 01 04 75 90 00 } //01 00 
		$a_00_4 = {33 d2 f7 f1 8b 45 08 0f b7 0c 50 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 e9 } //01 00 
		$a_00_5 = {8b c8 8b c7 33 d2 f7 f1 8a 04 53 30 06 47 3b 7c 24 18 75 } //00 00 
	condition:
		any of ($a_*)
 
}