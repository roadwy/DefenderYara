
rule Trojan_BAT_SnakeKeyLogger_AMMJ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.AMMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 7e ?? 00 00 04 8e 69 fe 04 0d 09 2d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}