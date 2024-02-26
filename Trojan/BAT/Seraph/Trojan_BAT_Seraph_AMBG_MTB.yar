
rule Trojan_BAT_Seraph_AMBG_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AMBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 1e 11 09 11 24 11 21 61 19 11 18 58 61 11 } //00 00 
	condition:
		any of ($a_*)
 
}