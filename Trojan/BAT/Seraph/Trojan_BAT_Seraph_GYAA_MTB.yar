
rule Trojan_BAT_Seraph_GYAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.GYAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {ff ff 11 03 28 90 01 01 00 00 0a 20 01 00 00 00 7e 90 01 01 00 00 04 7b 90 01 01 00 00 04 3a 90 01 01 ff ff ff 26 20 01 00 00 00 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}