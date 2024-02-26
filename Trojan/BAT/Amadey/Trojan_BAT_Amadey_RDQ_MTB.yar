
rule Trojan_BAT_Amadey_RDQ_MTB{
	meta:
		description = "Trojan:BAT/Amadey.RDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 08 1c 5a 58 0a 08 17 58 0c 08 1a } //00 00 
	condition:
		any of ($a_*)
 
}