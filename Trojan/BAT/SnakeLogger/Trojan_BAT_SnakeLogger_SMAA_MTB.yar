
rule Trojan_BAT_SnakeLogger_SMAA_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.SMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 0a 06 0b 16 0c 2b 19 00 02 08 7e ?? 00 00 04 08 91 05 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 7e ?? 00 00 04 8e 69 fe 04 0d 09 2d d9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}