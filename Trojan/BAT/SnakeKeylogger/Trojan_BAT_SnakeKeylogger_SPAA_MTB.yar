
rule Trojan_BAT_SnakeKeylogger_SPAA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0c 11 0d 61 13 0f 11 0f 11 0e 59 13 10 07 11 0a 11 10 11 08 5d d2 9c 00 11 07 17 58 13 07 11 07 08 fe 04 13 11 11 11 2d 8b } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}