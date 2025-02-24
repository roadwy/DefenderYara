
rule Trojan_BAT_ClipBanker_NIT_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 2c 6d 07 6f ?? 00 00 0a 0c 16 0d 2b 48 08 09 9a 13 04 07 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 11 04 1c 28 ?? 00 00 06 28 ?? 00 00 0a 2c 1f 11 05 7e 36 00 00 04 28 ?? 00 00 0a 2c 0d 07 11 04 7e 36 00 00 04 6f ?? 00 00 0a 17 0a 2b 02 16 0a 09 17 58 0d 09 08 8e 69 32 b2 06 2d 11 07 1c 28 ?? 00 00 06 7e 36 00 00 04 6f ?? 00 00 0a de 0d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}