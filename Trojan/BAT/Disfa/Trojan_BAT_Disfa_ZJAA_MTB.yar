
rule Trojan_BAT_Disfa_ZJAA_MTB{
	meta:
		description = "Trojan:BAT/Disfa.ZJAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {1f 5a 28 00 02 00 06 13 0b 2b d6 07 1e 11 05 16 1e 28 ?? 00 00 0a 1f 62 28 04 02 00 06 13 0b 2b c0 00 1a 13 0b 2b ba 00 19 13 0b 2b b4 08 6f ?? 00 00 0a 1e 5b 8d 05 00 00 01 13 05 16 13 0b 2b a0 73 30 00 00 0a 13 06 1b 13 0b 2b 94 } //3
		$a_03_1 = {04 08 09 11 05 6f ?? 00 00 0a 16 73 62 00 00 0a 13 08 11 08 11 06 28 ?? 02 00 06 00 de 15 } //2
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}