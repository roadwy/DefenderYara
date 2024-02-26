
rule Trojan_BAT_DCRat_RDF_MTB{
	meta:
		description = "Trojan:BAT/DCRat.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 18 6f 32 00 00 0a 06 6f 33 00 00 0a 0c 02 0d 08 09 16 09 } //00 00 
	condition:
		any of ($a_*)
 
}