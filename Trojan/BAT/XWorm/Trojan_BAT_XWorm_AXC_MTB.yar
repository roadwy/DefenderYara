
rule Trojan_BAT_XWorm_AXC_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 05 1d 28 09 00 00 0a 13 06 11 06 72 12 a6 01 70 28 0a 00 00 0a 13 07 11 07 11 05 28 0b 00 00 0a 00 11 07 28 0c 00 00 0a 26 00 de 12 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}