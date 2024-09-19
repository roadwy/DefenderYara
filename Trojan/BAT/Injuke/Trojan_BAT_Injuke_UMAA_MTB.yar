
rule Trojan_BAT_Injuke_UMAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.UMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 08 17 73 ?? 00 00 0a 13 04 2b 19 2b 1b 16 2b 1b 8e 69 2b 1a 09 6f ?? 00 00 0a 13 05 16 2d f5 1a 2c e7 de 34 11 04 2b e3 06 2b e2 06 2b e2 6f ?? 00 00 0a 2b df } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}