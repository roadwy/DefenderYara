
rule Trojan_BAT_Nanocore_ATRA_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ATRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 13 15 00 11 15 17 6f ?? 00 00 0a 00 11 15 18 6f ?? 00 00 0a 00 11 15 09 6f ?? 00 00 0a 00 11 15 11 09 6f ?? 00 00 0a 00 11 15 6f ?? 00 00 0a 11 0a 16 11 0a 8e 69 6f ?? 00 00 0a 13 0c 00 de 0d } //5
		$a_03_1 = {06 11 0f 7e ?? 00 00 04 11 0f 91 7e ?? 00 00 04 61 d2 9c 11 0f 17 58 13 0f 11 0f 7e ?? 00 00 04 8e 69 fe 04 13 10 11 10 2d d6 } //2
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=9
 
}