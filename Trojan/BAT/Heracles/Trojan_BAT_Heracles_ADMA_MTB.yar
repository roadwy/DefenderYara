
rule Trojan_BAT_Heracles_ADMA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ADMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 73 ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 11 06 11 05 09 11 04 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 07 2b 16 2b 18 16 2b 18 8e 69 2b 17 17 16 2c 1a 26 2b 1a 2b 1c 13 08 de 70 11 07 2b e6 08 2b e5 08 2b e5 6f ?? 00 00 0a 2b e2 0b 2b e4 11 06 2b e2 6f ?? 00 00 0a 2b dd } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}