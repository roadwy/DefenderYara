
rule Trojan_BAT_DarkTortilla_RDC_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8e 69 6f a6 00 00 0a 13 05 17 13 13 } //00 00 
	condition:
		any of ($a_*)
 
}