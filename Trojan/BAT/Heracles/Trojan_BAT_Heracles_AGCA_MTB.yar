
rule Trojan_BAT_Heracles_AGCA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AGCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 0c 12 02 28 ?? 00 00 0a 75 ?? 00 00 1b 0d 12 02 28 ?? 00 00 0a 73 ?? 00 00 0a 13 04 11 04 06 07 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 11 06 11 05 17 73 ?? 00 00 0a 13 07 11 07 09 16 09 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 28 ?? 00 00 0a 13 08 de 24 } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}