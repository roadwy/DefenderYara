
rule Trojan_BAT_FormBook_AEDW_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AEDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 00 07 17 8d 90 01 03 01 25 16 28 90 01 03 06 d2 9c 6f 90 01 03 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d b8 90 00 } //01 00 
		$a_01_1 = {62 00 6f 00 61 00 74 00 } //01 00 
		$a_01_2 = {47 65 74 50 69 78 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}