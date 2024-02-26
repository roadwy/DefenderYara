
rule Trojan_BAT_Banbra_AMAF_MTB{
	meta:
		description = "Trojan:BAT/Banbra.AMAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 28 90 01 01 00 00 0a 26 1f 90 01 01 1f 90 01 01 28 90 01 01 00 00 06 28 90 01 01 00 00 06 72 90 01 02 00 70 28 90 01 01 00 00 0a 0d 08 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}