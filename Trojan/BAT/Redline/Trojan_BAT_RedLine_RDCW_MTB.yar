
rule Trojan_BAT_RedLine_RDCW_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 06 28 3a 00 00 0a 0e 04 6f 3b 00 00 0a 6f 3c 00 00 0a 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}