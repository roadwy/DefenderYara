
rule Trojan_BAT_AveMaria_NECP_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NECP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2b 22 00 02 07 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 06 07 1a 5d 1f 0a 5a 91 61 d2 81 90 01 01 00 00 01 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d d4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}