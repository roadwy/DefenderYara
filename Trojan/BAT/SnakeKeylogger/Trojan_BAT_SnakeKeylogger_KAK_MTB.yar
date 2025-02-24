
rule Trojan_BAT_SnakeKeylogger_KAK_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.KAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {59 0d 03 19 8d ?? 00 00 01 25 16 11 08 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 08 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 08 20 ff 00 00 00 5f d2 9c } //1
		$a_03_1 = {5a 0d 19 8d ?? 00 00 01 25 16 12 06 28 ?? 00 00 0a 9c 25 17 12 06 28 ?? 00 00 0a 9c 25 18 12 06 28 ?? 00 00 0a 9c 13 09 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}