
rule Trojan_BAT_SnakeKeylogger_SGRG_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SGRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 5d 91 13 07 07 11 06 08 5d 08 58 08 5d 91 11 07 61 13 08 11 06 17 58 08 5d 08 58 08 5d 13 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_SnakeKeylogger_SGRG_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SGRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 08 7e 04 00 00 04 08 91 03 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 7e 04 00 00 04 8e 69 fe 04 0d 09 2d d9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}