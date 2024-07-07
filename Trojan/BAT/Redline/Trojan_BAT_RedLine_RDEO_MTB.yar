
rule Trojan_BAT_RedLine_RDEO_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 13 0b 02 11 06 8f 1a 00 00 01 25 71 1a 00 00 01 06 11 0b 91 61 d2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}