
rule Trojan_BAT_njRAT_MBS_MTB{
	meta:
		description = "Trojan:BAT/njRAT.MBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 5c 11 5a 11 5b 16 6f 90 01 01 00 00 0a 13 5e 12 5e 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 11 5b 17 d6 13 5b 11 5b 11 5d 31 da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}