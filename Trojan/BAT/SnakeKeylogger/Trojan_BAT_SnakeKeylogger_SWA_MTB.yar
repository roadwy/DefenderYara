
rule Trojan_BAT_SnakeKeylogger_SWA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 06 72 9f 00 00 70 03 07 94 8c 36 00 00 01 04 07 94 8c 36 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 00 07 17 58 0b 07 03 16 6f ?? 00 00 0a fe 02 16 fe 01 0c 08 2d c8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}