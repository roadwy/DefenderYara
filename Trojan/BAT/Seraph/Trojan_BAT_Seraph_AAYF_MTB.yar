
rule Trojan_BAT_Seraph_AAYF_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 0a 11 09 11 02 11 09 91 11 08 11 09 11 08 28 90 01 02 00 06 5d 6f 90 01 02 00 0a 61 d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}