
rule Trojan_BAT_SnakeLogger_FAS_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.FAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 07 2b 1f 00 09 08 11 07 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 6f 79 00 00 0a 00 00 11 07 18 58 13 07 11 07 08 6f 90 01 01 00 00 0a fe 04 13 08 11 08 2d d1 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}