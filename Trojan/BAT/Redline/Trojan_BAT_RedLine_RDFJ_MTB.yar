
rule Trojan_BAT_RedLine_RDFJ_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 6f 68 00 00 0a 16 9a 13 05 11 05 6f 69 00 00 0a 16 9a 13 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}