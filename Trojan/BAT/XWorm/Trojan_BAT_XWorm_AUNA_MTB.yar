
rule Trojan_BAT_XWorm_AUNA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AUNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 06 02 6f ?? 00 00 0a 73 ?? 00 00 0a 0b 07 06 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0c 2b 15 2b 16 16 2b 16 8e 69 2b 15 2b 1a 2b 1b 2b 20 2b 21 2b 26 de 4c 08 2b e8 03 2b e7 03 2b e7 6f ?? 00 00 0a 2b e4 08 2b e3 6f ?? 00 00 0a 2b de 07 2b dd 6f ?? 00 00 0a 2b d8 0d 2b d7 } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}