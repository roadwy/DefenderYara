
rule Trojan_BAT_Seraph_SPDD_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {2b 15 2b 16 14 2b 1a de 45 11 04 2b ea 08 2b e9 6f 90 01 03 0a 2b e4 08 2b e8 6f 90 01 03 0a 2b e3 6f 90 01 03 0a 2b df 11 04 2c 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}