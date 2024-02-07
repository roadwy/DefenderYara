
rule Trojan_BAT_FormBook_AGMP_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AGMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0b 2b 35 06 07 06 8e 69 5d 06 07 06 8e 69 5d 91 11 04 07 1f 16 5d 6f 90 01 03 0a 61 06 07 17 58 06 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 07 15 58 0b 07 16 fe 04 16 fe 01 13 07 11 07 2d be 90 00 } //01 00 
		$a_01_1 = {51 00 4c 00 43 00 48 00 41 00 70 00 70 00 6c 00 65 00 5f 00 42 00 55 00 53 00 } //00 00  QLCHApple_BUS
	condition:
		any of ($a_*)
 
}