
rule Trojan_BAT_Njrat_NB_MTB{
	meta:
		description = "Trojan:BAT/Njrat.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {1f 6f 91 61 1f 90 01 01 5f 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}