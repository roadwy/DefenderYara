
rule Trojan_BAT_InjectorNetT_AJLA_MTB{
	meta:
		description = "Trojan:BAT/InjectorNetT.AJLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 2d 20 72 16 06 00 70 38 94 00 00 00 15 3a 98 00 00 00 26 72 48 06 00 70 38 93 00 00 00 38 98 00 00 00 38 99 00 00 00 75 20 00 00 1b 38 99 00 00 00 16 2d cb 38 97 00 00 00 38 9c 00 00 00 73 ?? 00 00 0a 13 04 11 04 09 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 2b 15 08 16 08 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 06 de 29 11 05 2b e7 } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}