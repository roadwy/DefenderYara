
rule Trojan_BAT_FormBook_AAWC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AAWC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 08 07 8e 69 5d 02 07 08 07 8e 69 5d 91 11 04 08 11 04 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 28 90 01 01 00 00 0a d2 07 08 17 58 07 8e 69 5d 91 28 90 01 01 00 00 0a d2 59 20 00 01 00 00 58 28 90 01 01 00 00 06 28 90 01 01 00 00 0a d2 9c 08 15 58 0c 08 16 fe 04 16 fe 01 13 07 11 07 2d a8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}