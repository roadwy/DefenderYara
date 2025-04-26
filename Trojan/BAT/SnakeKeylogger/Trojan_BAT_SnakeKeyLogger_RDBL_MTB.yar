
rule Trojan_BAT_SnakeKeyLogger_RDBL_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 11 04 28 01 00 00 2b 8e 69 6f 08 00 00 0a 08 6f 09 00 00 0a 13 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}