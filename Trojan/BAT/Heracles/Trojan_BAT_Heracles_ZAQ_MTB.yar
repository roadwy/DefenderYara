
rule Trojan_BAT_Heracles_ZAQ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ZAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {0c 08 06 28 ?? 00 00 0a 07 28 ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 02 28 ?? 00 00 06 75 ?? 00 00 1b 13 06 11 05 11 06 16 11 06 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 07 de 22 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}