
rule Trojan_BAT_CobaltStrike_H_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {04 16 07 7e 90 01 01 00 00 04 8e 69 28 90 01 01 00 00 06 07 d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}