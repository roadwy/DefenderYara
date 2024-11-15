
rule Trojan_BAT_SnakeKeyLogger_RDCA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 07 09 28 04 00 00 06 00 1d 28 13 00 00 0a 08 28 12 00 00 0a 13 04 09 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}