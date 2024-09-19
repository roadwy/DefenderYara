
rule Trojan_BAT_QuasarRAT_RDF_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 6f 4b 01 00 0a 13 07 73 9b 00 00 0a 13 04 11 04 11 07 17 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}