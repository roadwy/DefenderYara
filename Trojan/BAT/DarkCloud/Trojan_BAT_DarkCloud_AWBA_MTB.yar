
rule Trojan_BAT_DarkCloud_AWBA_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AWBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {38 d4 00 00 00 08 72 ?? 02 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 1c 2c ed 17 2c ea 08 72 ?? 02 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 2b 1e 2b 20 16 07 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 28 ?? 00 00 0a 13 06 1c 2c e2 de 32 11 05 2b de 07 2b dd } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}