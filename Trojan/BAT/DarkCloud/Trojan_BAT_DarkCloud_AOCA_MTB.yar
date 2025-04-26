
rule Trojan_BAT_DarkCloud_AOCA_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AOCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {ff ff ff 11 02 11 02 6f ?? 00 00 0a 11 02 6f ?? 00 00 0a 6f ?? 00 00 0a 13 11 20 02 00 00 00 38 ?? ff ff ff 11 02 72 ab 00 00 70 28 ?? 00 00 0a 6f } //3
		$a_03_1 = {11 13 11 11 17 73 ?? 00 00 0a 13 05 } //1
		$a_03_2 = {11 05 11 0e 16 11 0e 8e 69 6f ?? 00 00 0a 20 } //1
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}