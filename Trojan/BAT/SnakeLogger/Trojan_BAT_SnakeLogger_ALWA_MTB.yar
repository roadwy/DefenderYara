
rule Trojan_BAT_SnakeLogger_ALWA_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.ALWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 25 07 6f ?? 00 00 0a 25 08 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 0d 09 6f ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 13 05 03 20 ?? ?? 00 00 28 ?? 00 00 06 11 05 6f ?? 00 00 06 17 13 06 de 33 } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}