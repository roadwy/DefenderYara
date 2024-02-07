
rule Trojan_BAT_FormBook_AAB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 13 08 2b 44 00 16 13 09 2b 2c 00 09 11 04 11 08 58 11 07 11 09 58 6f 90 01 03 0a 13 0a 12 0a 28 90 01 03 0a 13 0b 08 07 11 0b 9c 07 17 58 0b 11 09 17 58 13 09 00 11 09 17 fe 04 13 0c 11 0c 2d c9 90 00 } //01 00 
		$a_01_1 = {42 00 69 00 6f 00 73 00 69 00 6d 00 } //00 00  Biosim
	condition:
		any of ($a_*)
 
}