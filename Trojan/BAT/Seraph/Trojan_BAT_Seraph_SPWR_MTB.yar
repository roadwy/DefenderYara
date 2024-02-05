
rule Trojan_BAT_Seraph_SPWR_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPWR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {0b 73 0b 00 00 0a 0c 08 07 17 73 0c 00 00 0a 0d 28 90 01 03 06 16 9a 75 01 00 00 1b 13 04 09 11 04 16 11 04 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}