
rule Trojan_BAT_SnakeKeylogger_MBDT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MBDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 07 18 6f ?? 00 00 0a 20 03 02 00 00 28 ?? 00 00 0a 13 09 11 06 11 09 8c ?? 00 00 01 6f ?? 00 00 0a 26 11 07 18 58 13 07 00 11 07 11 05 6f ?? 00 00 0a fe 04 13 0a 11 0a 2d c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}