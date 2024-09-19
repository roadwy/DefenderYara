
rule Trojan_BAT_SnakeKeyLogger_PN_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.PN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 2d 0b 2b 0b 72 15 00 00 70 2b 07 2b 0c de 1a 07 2b f2 6f 17 00 00 0a 2b f2 0a 2b f1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}