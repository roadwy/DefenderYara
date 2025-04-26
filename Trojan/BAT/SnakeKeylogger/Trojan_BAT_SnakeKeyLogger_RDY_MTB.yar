
rule Trojan_BAT_SnakeKeyLogger_RDY_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 11 00 00 0a 6f 12 00 00 0a 0b 73 13 00 00 0a 0c 02 28 06 00 00 06 75 01 00 00 1b 73 14 00 00 0a 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}