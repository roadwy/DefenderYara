
rule Trojan_BAT_VenomRAT_B_MTB{
	meta:
		description = "Trojan:BAT/VenomRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {04 06 25 0b 6f 90 09 16 00 04 28 90 01 01 00 00 0a 02 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0a 7e 90 00 } //02 00 
		$a_03_1 = {03 8e 69 6f 90 01 01 00 00 0a 0a 06 0b 90 09 09 00 04 6f 90 01 01 00 00 0a 02 0e 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}