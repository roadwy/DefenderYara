
rule Trojan_BAT_Zusy_AMBE_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 13 08 12 08 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 16 09 06 1a 28 90 01 01 00 00 0a 00 06 1a 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}