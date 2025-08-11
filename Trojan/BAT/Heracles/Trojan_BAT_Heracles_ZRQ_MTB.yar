
rule Trojan_BAT_Heracles_ZRQ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ZRQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 26 0b 20 0a 16 0a 00 28 ?? 00 00 06 28 ?? 00 00 0a 25 26 0c 28 ?? 00 00 0a 25 26 0d 00 09 07 6f ?? 00 00 0a 00 09 08 6f ?? 00 00 0a 00 09 1f 0c 28 ?? 00 00 06 6f ?? 00 00 0a 00 09 1f 10 28 ?? 00 00 06 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 04 00 11 04 06 1f 14 28 ?? 00 00 06 06 8e 69 6f ?? 00 00 0a 25 26 13 05 de 63 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}