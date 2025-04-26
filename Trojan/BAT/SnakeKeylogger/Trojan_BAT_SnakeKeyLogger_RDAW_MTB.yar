
rule Trojan_BAT_SnakeKeyLogger_RDAW_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 59 13 04 06 09 28 03 00 00 2b 11 04 28 04 00 00 2b 28 05 00 00 2b 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}