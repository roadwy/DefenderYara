
rule Trojan_BAT_SnakeKeyLogger_RDCI_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 14 00 00 0a 72 a1 00 00 70 73 15 00 00 0a 28 16 00 00 0a 6f 17 00 00 0a 13 13 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}