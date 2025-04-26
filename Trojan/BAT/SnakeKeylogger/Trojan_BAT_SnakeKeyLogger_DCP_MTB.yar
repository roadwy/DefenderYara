
rule Trojan_BAT_SnakeKeyLogger_DCP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.DCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 0f 11 0f 1b 5a 20 bb 00 00 00 61 d2 9c 00 11 0f 17 58 13 0f 11 0f 11 06 8e 69 fe 04 13 10 11 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}