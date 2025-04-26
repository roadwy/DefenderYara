
rule Trojan_BAT_SnakeKeylogger_NEI_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 04 1f 0a 6f ?? 00 00 0a 13 04 07 06 11 04 93 6f ?? 00 00 0a 26 00 09 17 58 0d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}