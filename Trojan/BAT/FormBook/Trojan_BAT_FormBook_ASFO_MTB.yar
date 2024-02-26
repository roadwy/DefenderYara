
rule Trojan_BAT_FormBook_ASFO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ASFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 11 07 07 8e 69 6a 5d d4 07 11 07 07 8e 69 6a 5d d4 91 08 11 07 08 8e 69 6a 5d d4 91 61 28 90 01 01 00 00 06 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 28 90 01 01 00 00 06 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 01 00 00 06 9c 11 07 17 6a 58 13 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}