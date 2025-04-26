
rule Trojan_BAT_SnakeKeyLogger_RDW_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 0a 00 00 0a 6f 0b 00 00 0a 0b 73 0c 00 00 0a 0c 02 28 02 00 00 06 75 03 00 00 1b 73 0d 00 00 0a 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}