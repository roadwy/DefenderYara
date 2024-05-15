
rule Trojan_BAT_Heracles_SPDO_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SPDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {91 61 d2 13 90 01 01 11 90 01 01 07 11 90 01 01 17 58 09 5d 91 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}