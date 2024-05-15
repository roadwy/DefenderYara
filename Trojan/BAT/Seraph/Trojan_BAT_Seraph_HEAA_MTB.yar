
rule Trojan_BAT_Seraph_HEAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.HEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 00 0a 0a 06 28 90 01 02 00 0a 02 06 28 90 01 01 02 00 0a 7d 90 01 01 00 00 04 de 03 26 de 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}