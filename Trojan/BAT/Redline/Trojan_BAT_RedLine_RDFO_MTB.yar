
rule Trojan_BAT_RedLine_RDFO_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 28 15 00 00 06 13 06 11 05 11 06 16 11 06 8e 69 6f 24 00 00 0a 28 16 00 00 06 13 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}