
rule Trojan_BAT_Seraph_GBAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.GBAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {14 13 04 2b 14 00 28 90 01 01 00 00 06 13 04 11 04 28 90 01 01 00 00 0a de 03 26 de 00 11 04 2c e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}