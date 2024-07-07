
rule Trojan_BAT_PureCrypter_OHAA_MTB{
	meta:
		description = "Trojan:BAT/PureCrypter.OHAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 06 72 01 00 00 70 28 90 01 01 01 00 06 6f 90 01 01 00 00 0a 06 72 5b 00 00 70 28 90 01 01 01 00 06 6f 90 01 01 00 00 0a 06 06 6f 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0b 90 00 } //2
		$a_03_1 = {13 04 09 11 04 16 11 04 8e 69 6f 90 01 01 00 00 0a 09 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 06 90 00 } //2
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}