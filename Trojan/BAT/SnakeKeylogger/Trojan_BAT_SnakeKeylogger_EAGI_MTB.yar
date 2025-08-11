
rule Trojan_BAT_SnakeKeylogger_EAGI_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EAGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 47 11 0e 1f 1f 5a d2 61 d2 52 11 0e 17 58 13 0e 11 0e 11 08 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}