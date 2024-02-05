
rule Trojan_BAT_FormBook_ERV_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ERV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0a 03 04 20 90 01 04 5d 03 02 20 90 01 04 04 28 90 01 03 06 03 04 17 58 20 90 01 04 5d 91 59 06 58 06 5d d2 9c 03 0b 2b 00 90 00 } //01 00 
		$a_03_1 = {02 05 04 5d 91 03 05 1f 16 5d 6f 90 01 03 0a 61 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}