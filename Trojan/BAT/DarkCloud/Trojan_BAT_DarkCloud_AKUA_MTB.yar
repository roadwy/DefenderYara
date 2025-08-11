
rule Trojan_BAT_DarkCloud_AKUA_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AKUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 73 ?? 00 00 0a 13 05 11 05 11 04 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 06 2b 1c 2b 1e 16 2b 1e 8e 69 2b 1d 2b 22 2b 24 2b 29 2b 2a 2b 2c 6f ?? 00 00 06 17 0b de 6a 11 06 2b e0 06 2b df 06 2b df 6f ?? 00 00 0a 2b dc 11 06 2b da 6f ?? 00 00 0a 2b d5 03 2b d4 11 05 2b d2 6f ?? 00 00 0a 2b cd } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}