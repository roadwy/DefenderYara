
rule Trojan_BAT_SnakeKeyLogger_RDAA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 31 00 00 0a 05 03 02 8e 69 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}