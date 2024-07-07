
rule Trojan_BAT_SnakeKeyLogger_RDAO_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {04 8e 69 6f 39 00 00 0a 0a 06 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}