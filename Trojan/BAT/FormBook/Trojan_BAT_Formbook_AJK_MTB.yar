
rule Trojan_BAT_Formbook_AJK_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0d 2b 49 00 07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 08 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 28 90 01 03 0a 07 09 17 58 07 8e 69 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 03 0a d2 9c 09 15 58 0d 00 09 16 fe 04 16 fe 01 13 07 11 07 2d aa 90 00 } //01 00 
		$a_01_1 = {43 00 75 00 61 00 48 00 61 00 6e 00 67 00 44 00 54 00 } //00 00  CuaHangDT
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Formbook_AJK_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.AJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 28 00 08 09 11 04 6f 90 01 03 0a 13 0b 12 0b 28 90 01 03 0a 13 0c 07 11 05 11 0c 9c 11 05 17 58 13 05 00 11 04 17 58 13 04 11 04 08 6f 90 01 03 0a fe 04 13 0d 11 0d 2d c8 00 09 17 58 0d 09 08 6f 90 01 03 0a fe 04 13 0e 11 0e 2d ae 90 00 } //01 00 
		$a_01_1 = {6f 00 62 00 73 00 74 00 61 00 63 00 6c 00 65 00 5f 00 61 00 76 00 6f 00 69 00 64 00 61 00 6e 00 63 00 65 00 31 00 } //00 00  obstacle_avoidance1
	condition:
		any of ($a_*)
 
}