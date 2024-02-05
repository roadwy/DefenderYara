
rule Trojan_BAT_FormBook_AILF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AILF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 08 2b 18 07 06 11 08 9a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 00 11 08 17 58 13 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}