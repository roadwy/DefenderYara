
rule Trojan_BAT_AsyncRAT_BO_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 94 d6 20 00 01 00 00 5d 94 13 10 02 06 17 da 17 6f ?? 00 00 0a 6f ?? 00 00 0a 16 93 13 0e 11 0e 28 ?? 00 00 0a 13 0f 11 0f 11 10 61 13 0d 08 11 0d 28 ?? 00 00 0a 6f ?? 00 00 0a 26 12 00 28 ?? 00 00 0a 06 17 da 28 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}