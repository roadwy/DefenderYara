
rule Trojan_BAT_Amadey_RDM_MTB{
	meta:
		description = "Trojan:BAT/Amadey.RDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 1e 00 00 0a 02 7b 0c 00 00 04 6f 1f 00 00 0a 13 05 } //00 00 
	condition:
		any of ($a_*)
 
}