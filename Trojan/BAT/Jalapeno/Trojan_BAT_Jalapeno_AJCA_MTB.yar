
rule Trojan_BAT_Jalapeno_AJCA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AJCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 26 06 72 f7 01 00 70 18 18 8d ?? 00 00 01 25 16 04 a2 25 17 05 a2 28 ?? 00 00 0a 0b 03 73 ?? 00 00 0a 0c 08 07 74 ?? 00 00 01 16 73 ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 00 09 11 04 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 13 05 de 23 } //3
		$a_03_1 = {0a 26 06 72 d9 01 00 70 1e 17 8d ?? 00 00 01 25 16 04 a2 28 ?? 00 00 0a 26 06 72 e9 01 00 70 1e 17 8d ?? 00 00 01 25 16 05 a2 } //2
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}