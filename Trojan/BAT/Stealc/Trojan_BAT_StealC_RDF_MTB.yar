
rule Trojan_BAT_StealC_RDF_MTB{
	meta:
		description = "Trojan:BAT/StealC.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 28 58 00 00 06 28 5a 00 00 06 6f 33 00 00 0a 02 16 02 8e 69 6f 34 00 00 0a 0b } //00 00 
	condition:
		any of ($a_*)
 
}