
rule Trojan_BAT_Heracles_ATBA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ATBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 72 ?? 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 17 73 ?? 00 00 0a 13 04 16 2d 16 2b 16 2b 18 16 2b 18 8e 69 1b 2d 16 26 26 26 26 2b 17 2b 18 2b 1d de 48 11 04 2b e6 06 2b e5 06 2b e5 6f ?? 00 00 0a 2b e7 09 2b e6 6f ?? 00 00 0a 2b e1 13 05 2b df } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}