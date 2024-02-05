
rule Trojan_BAT_Seraph_ASDX_MTB{
	meta:
		description = "Trojan:BAT/Seraph.ASDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 04 02 1f 10 11 04 16 02 8e 69 1f 10 da 28 90 01 01 00 00 0a 00 00 73 90 01 01 00 00 0a 13 05 11 05 07 6f 90 01 01 00 00 0a 00 11 05 17 6f 90 01 01 00 00 0a 00 11 05 09 6f 90 01 01 00 00 0a 00 00 11 05 6f 90 01 01 00 00 0a 13 06 11 06 11 04 16 11 04 8e 69 6f 90 01 01 00 00 0a 13 07 11 07 0a de 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}