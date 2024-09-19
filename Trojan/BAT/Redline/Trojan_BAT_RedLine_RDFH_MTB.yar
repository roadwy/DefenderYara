
rule Trojan_BAT_RedLine_RDFH_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 11 13 8f 14 00 00 01 25 71 14 00 00 01 06 11 1c 91 61 d2 81 14 00 00 01 11 13 17 58 13 13 11 13 02 8e 69 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}