
rule Trojan_BAT_SnakeKeylogger_NEG_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8f 07 00 00 01 25 47 7e 5d 00 00 04 19 11 0e 5f 19 62 1f 1f 5f 63 d2 61 d2 52 17 11 0e 58 13 0e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}