
rule Trojan_BAT_Seraph_SXC_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_03_0 = {06 20 00 01 00 00 6f 90 01 03 0a 06 7e 01 00 00 04 28 90 01 03 0a 6f 90 01 03 0a 06 7e 02 00 00 04 28 90 01 03 0a 6f 90 01 03 0a 06 06 6f 90 01 03 0a 06 6f 90 01 03 0a 6f 90 01 03 0a 0b 14 0c 38 44 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}