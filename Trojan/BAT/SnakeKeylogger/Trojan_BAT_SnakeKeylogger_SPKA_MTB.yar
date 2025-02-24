
rule Trojan_BAT_SnakeKeylogger_SPKA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 03 04 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0a de 09 26 28 ?? 00 00 2b 0a de 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}