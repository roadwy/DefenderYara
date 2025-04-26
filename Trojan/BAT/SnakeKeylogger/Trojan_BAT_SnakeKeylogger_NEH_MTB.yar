
rule Trojan_BAT_SnakeKeylogger_NEH_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 06 07 6f 7e 00 00 0a 6f ?? 00 00 0a 00 07 16 6f ?? 00 00 0a 00 16 0c 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}