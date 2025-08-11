
rule Trojan_BAT_XWorm_ARZA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ARZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 03 6f ?? 00 00 0a 07 04 6f ?? 00 00 0a 07 17 6f ?? 00 00 0a 07 18 6f ?? 00 00 0a 07 6f ?? 00 00 0a 0c 06 73 ?? 00 00 0a 0d 09 08 16 73 ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 11 04 11 05 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 06 de 36 } //4
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {44 65 63 72 79 70 74 46 72 6f 6d 42 61 73 65 36 34 } //1 DecryptFromBase64
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}