
rule Trojan_BAT_FormBook_AJF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 13 09 2b 36 00 11 06 11 09 09 11 09 91 11 05 61 11 04 11 07 91 61 28 90 01 03 0a 9c 11 07 1f 15 fe 01 13 0a 11 0a 2c 05 16 13 07 2b 06 11 07 17 58 13 07 00 11 09 17 58 13 09 11 09 09 8e 69 17 59 fe 02 16 fe 01 13 0b 11 0b 2d b8 90 00 } //01 00 
		$a_01_1 = {53 00 6b 00 79 00 6c 00 61 00 72 00 6b 00 } //00 00 
	condition:
		any of ($a_*)
 
}