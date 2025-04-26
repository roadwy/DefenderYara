
rule Trojan_BAT_SnakeKeylogger_KAE_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 08 18 5a 6f ?? 00 00 0a 28 ?? 00 00 0a 1a 62 72 ?? ?? ?? ?? 03 08 18 5a 17 58 6f ?? 00 00 0a 28 ?? 00 00 0a 60 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 0d 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}