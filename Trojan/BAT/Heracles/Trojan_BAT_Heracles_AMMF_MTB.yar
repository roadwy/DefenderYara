
rule Trojan_BAT_Heracles_AMMF_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {04 07 09 16 6f 90 01 01 00 00 0a 13 90 01 01 12 90 01 01 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}