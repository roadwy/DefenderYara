
rule Trojan_BAT_RedLine_RDAO_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0e 29 00 fe 0c 29 00 fe 0c 2a 00 58 fe 0e 29 00 fe 0c 29 00 fe 0c 29 00 19 62 61 fe 0e 29 00 fe 0c 29 00 fe 0c 2b 00 58 fe 0e 29 00 fe 0c 2a 00 1f 13 62 fe 0c 27 00 59 fe 0c 2a 00 61 fe 0c 29 00 58 fe 0e 29 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}