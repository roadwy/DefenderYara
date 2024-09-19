
rule Trojan_BAT_RedLine_RDFB_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 11 20 02 11 20 91 66 d2 9c 02 11 20 8f 1d 00 00 01 25 71 1d 00 00 01 1f 64 58 d2 81 1d 00 00 01 02 11 20 8f 1d 00 00 01 25 71 1d 00 00 01 20 92 00 00 00 59 d2 81 1d 00 00 01 00 11 20 17 58 13 20 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}