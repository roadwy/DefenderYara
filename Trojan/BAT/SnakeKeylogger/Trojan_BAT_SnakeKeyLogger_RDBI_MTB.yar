
rule Trojan_BAT_SnakeKeyLogger_RDBI_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 5d 08 58 08 5d 13 06 07 11 06 08 5d 08 58 08 5d 91 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}