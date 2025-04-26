
rule Trojan_BAT_RedLine_RDFK_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 28 bf 00 00 0a 0c 28 c0 00 00 0a 6f c1 00 00 0a 08 6f c2 00 00 0a 17 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_RedLine_RDFK_MTB_2{
	meta:
		description = "Trojan:BAT/RedLine.RDFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 66 d2 9c 02 06 8f 36 00 00 01 25 71 36 00 00 01 1f 79 59 d2 81 36 00 00 01 02 06 8f 36 00 00 01 25 71 36 00 00 01 1f 57 59 d2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}