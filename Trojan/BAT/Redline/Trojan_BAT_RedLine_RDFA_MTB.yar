
rule Trojan_BAT_RedLine_RDFA_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 08 6f 4b 00 00 0a 0d 09 03 16 03 8e 69 6f 4c 00 00 0a 13 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}