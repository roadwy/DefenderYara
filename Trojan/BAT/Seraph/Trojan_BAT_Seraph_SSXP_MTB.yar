
rule Trojan_BAT_Seraph_SSXP_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SSXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {7e 02 00 00 04 08 6f 90 01 03 0a 6f 90 01 03 0a 2c 06 08 6f 90 01 03 0a de 03 26 de 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}