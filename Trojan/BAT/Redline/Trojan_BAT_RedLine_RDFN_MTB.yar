
rule Trojan_BAT_RedLine_RDFN_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 06 6f 2d 00 00 0a 06 6f 2e 00 00 0a 6f 2f 00 00 0a 03 6f 2a 00 00 0a 16 03 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}