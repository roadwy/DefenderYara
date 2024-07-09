
rule Trojan_BAT_Crysan_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 72 ?? 00 00 70 28 ?? 00 00 0a 07 72 ?? 00 00 70 6f ?? 00 00 0a 74 ?? 00 00 1b 28 ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 06 72 ?? 00 00 70 28 ?? 00 00 0a 07 72 ?? 00 00 70 6f ?? 00 00 0a 74 ?? 00 00 1b 28 ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 de 14 } //1
		$a_80_1 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //WriteAllBytes  1
		$a_80_2 = {47 65 74 4f 62 6a 65 63 74 } //GetObject  1
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}