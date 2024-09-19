
rule Trojan_BAT_SnakeKeylogger_SPBF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 0e 00 00 04 6f ?? 00 00 0a 00 25 7e 0f 00 00 04 6f ?? 00 00 0a 00 0a 06 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c 2b 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}