
rule Trojan_BAT_CobaltStrike_RDC_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 0b 91 13 0c 7e 90 01 04 11 0b 11 0c 07 59 d2 9c 06 7e 90 01 04 11 0b 91 6f 90 01 04 11 0b 17 58 13 0b 11 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}