
rule Trojan_BAT_Seraph_AATN_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AATN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 07 16 73 90 01 01 00 00 0a 13 04 2b 12 2b 14 2b 15 7e 90 01 01 00 00 04 2b 15 2b 16 14 2b 1a de 45 11 04 2b ea 08 2b e9 6f 90 01 01 00 00 0a 2b e4 08 2b e8 6f 90 01 01 00 00 0a 2b e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}