
rule Trojan_BAT_ozirp_RDF_MTB{
	meta:
		description = "Trojan:BAT/ozirp.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 2f 00 00 0a 6f 33 00 00 0a 25 17 6f 34 00 00 0a 25 02 } //00 00 
	condition:
		any of ($a_*)
 
}