
rule Trojan_BAT_RedLine_RDEJ_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 47 1f 7b 61 d2 52 06 17 58 0a 06 02 8e 69 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}