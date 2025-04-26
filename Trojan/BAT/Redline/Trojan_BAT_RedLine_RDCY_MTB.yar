
rule Trojan_BAT_RedLine_RDCY_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 09 a2 14 28 84 00 00 0a 1b 8c 57 00 00 01 28 8c 00 00 0a a2 14 28 8d 00 00 0a 00 09 08 12 03 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}