
rule Trojan_BAT_SnakeKeyLogger_RDAZ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 7e 88 01 00 04 6f 4b 00 00 0a 06 7e 89 01 00 04 6f 4c 00 00 0a 06 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}