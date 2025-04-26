
rule Trojan_BAT_SnakeKeylogger_SPDT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 73 22 00 00 0a 0d 09 06 07 6f ?? 00 00 0a 13 04 73 24 00 00 0a 13 05 11 05 11 04 17 73 25 00 00 0a 13 06 11 06 08 16 08 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 07 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}