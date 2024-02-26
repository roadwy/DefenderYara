
rule Trojan_BAT_Seraph_SPQN_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPQN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 06 16 06 8e 69 28 90 01 03 0a 06 0b dd 90 01 03 00 26 de e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}