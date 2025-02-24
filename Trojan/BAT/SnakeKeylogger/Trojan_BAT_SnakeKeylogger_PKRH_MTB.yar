
rule Trojan_BAT_SnakeKeylogger_PKRH_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.PKRH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 06 11 09 7e ?? 00 00 04 11 09 91 28 ?? 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 11 09 07 8e 69 5d 91 61 d2 9c 00 11 09 17 58 13 09 11 09 7e ?? 00 00 04 8e 69 fe 04 13 0a 11 0a 2d c3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}