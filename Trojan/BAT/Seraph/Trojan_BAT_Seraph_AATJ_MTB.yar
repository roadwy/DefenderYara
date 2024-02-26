
rule Trojan_BAT_Seraph_AATJ_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AATJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 13 04 38 90 01 01 00 00 00 08 11 04 16 6f 90 01 01 00 00 0a 13 05 12 05 28 90 01 01 00 00 0a 13 06 09 11 06 6f 90 01 01 00 00 0a 11 04 17 58 13 04 11 04 08 6f 90 01 01 00 00 0a 32 d4 09 6f 90 01 01 00 00 0a 13 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}