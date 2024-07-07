
rule Trojan_BAT_SnakeKeyLogger_RDAU_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 05 1f 16 5d 91 13 08 07 11 05 91 11 08 61 13 09 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}