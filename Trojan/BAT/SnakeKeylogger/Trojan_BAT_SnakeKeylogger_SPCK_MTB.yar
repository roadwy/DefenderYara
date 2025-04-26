
rule Trojan_BAT_SnakeKeylogger_SPCK_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 19 00 02 06 7e ?? 00 00 04 06 91 04 06 05 8e 69 5d 91 61 d2 9c 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69 fe 04 0b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}