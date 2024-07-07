
rule Trojan_BAT_BitRAT_ABFZ_MTB{
	meta:
		description = "Trojan:BAT/BitRAT.ABFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {1e 5b 6f 1d 00 00 0a 6f 20 00 00 0a 06 17 6f 21 00 00 0a 11 05 0d 07 06 6f 22 00 00 0a 17 73 23 00 00 0a 13 04 11 04 09 16 09 8e 69 6f 24 00 00 0a 17 2c f1 de 0b 11 04 6f 10 00 00 0a 16 2d f6 dc 07 6f 25 00 00 0a 13 08 16 3a 66 ff ff ff de 2e } //2
		$a_01_1 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}