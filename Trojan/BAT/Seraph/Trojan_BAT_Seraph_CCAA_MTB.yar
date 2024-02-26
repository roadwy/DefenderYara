
rule Trojan_BAT_Seraph_CCAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.CCAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 08 28 02 00 00 2b 28 90 01 01 00 00 2b 13 08 20 01 00 00 00 7e 90 01 01 00 00 04 7b 90 01 01 00 00 04 3a 90 01 01 ff ff ff 26 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}