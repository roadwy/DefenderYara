
rule Trojan_BAT_SnakeKeyLogger_RDCD_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 06 07 6f 11 00 00 0a 13 04 73 12 00 00 0a 13 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}