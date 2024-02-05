
rule Trojan_BAT_FormBook_ABKY_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABKY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 90 01 03 0a d2 6f 90 01 03 0a 00 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d d8 90 00 } //01 00 
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2e 00 49 00 4a 00 53 00 46 00 49 00 48 00 42 00 } //00 00 
	condition:
		any of ($a_*)
 
}