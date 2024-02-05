
rule Trojan_BAT_Formbook_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 08 09 5d 13 09 11 08 11 04 5d 13 0a 07 11 09 91 13 0b 08 11 0a 6f 90 01 01 00 00 0a 13 0c 02 07 11 08 28 90 01 01 00 00 06 13 0d 02 11 0b 11 0c 11 0d 28 90 01 01 00 00 06 13 0e 07 11 09 11 0e 20 00 01 00 00 5d d2 9c 11 08 17 59 13 08 11 08 16 2f b2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}