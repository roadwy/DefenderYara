
rule Trojan_BAT_Seraph_FAG_MTB{
	meta:
		description = "Trojan:BAT/Seraph.FAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 01 18 5b 8d 90 01 01 00 00 01 13 02 38 90 01 01 ff ff ff 11 00 28 90 01 01 00 00 06 13 01 38 90 01 01 ff ff ff 11 02 11 03 18 5b 11 00 11 03 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 06 9c 20 03 00 00 00 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}