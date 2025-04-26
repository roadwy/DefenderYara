
rule Trojan_BAT_RedLine_RDFG_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 6f ad 00 00 0a 28 ae 00 00 0a 0d 09 6f af 00 00 0a 16 9a 13 04 11 04 02 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}