
rule Trojan_BAT_SnakeKeylogger_KAL_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.KAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 16 08 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 08 1e 63 20 ff 00 00 00 5f d2 9c 25 18 08 20 ff 00 00 00 5f d2 9c } //1
		$a_03_1 = {06 18 5a 0a 19 8d ?? 00 00 01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}