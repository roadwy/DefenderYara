
rule Trojan_BAT_FormBook_AJSM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AJSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {18 5a 1f 16 58 0a 2b 43 06 03 8e 69 5d 0b 06 04 6f 90 01 03 0a 5d 0c 03 07 91 0d 04 08 6f 90 01 03 0a 13 04 02 03 06 28 90 01 03 06 13 05 02 09 11 04 11 05 28 90 01 03 06 13 06 03 07 11 06 20 00 01 00 00 5d d2 9c 06 17 59 0a 06 16 fe 04 16 fe 01 13 07 11 07 2d b0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}