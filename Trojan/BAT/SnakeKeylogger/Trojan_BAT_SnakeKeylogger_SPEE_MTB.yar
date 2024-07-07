
rule Trojan_BAT_SnakeKeylogger_SPEE_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 07 06 17 58 20 90 01 03 00 5d 91 09 58 09 5d 59 d2 9c 06 17 58 0a 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}