
rule Trojan_BAT_FormBook_CY_MTB{
	meta:
		description = "Trojan:BAT/FormBook.CY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {09 07 17 59 6f 90 01 01 00 00 0a 08 8e 69 58 13 08 09 07 6f 90 01 01 00 00 0a 11 08 59 13 09 11 09 8d 90 01 01 00 00 01 13 04 06 11 08 11 04 16 11 09 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}