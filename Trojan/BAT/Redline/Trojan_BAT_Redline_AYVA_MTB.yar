
rule Trojan_BAT_Redline_AYVA_MTB{
	meta:
		description = "Trojan:BAT/Redline.AYVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 2b 24 2b 26 16 2b 26 8e 69 2b 25 2b 2a 2b 2c 2b 31 2b 33 2b 38 11 06 03 72 ?? ?? 00 70 28 ?? ?? 00 06 17 0b de 5c 11 05 2b d8 06 2b d7 06 2b d7 6f ?? 00 00 0a 2b d4 11 05 2b d2 6f ?? 00 00 0a 2b cd 11 04 2b cb 6f ?? 00 00 0a 2b c6 13 06 2b c4 } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}