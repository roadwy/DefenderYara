
rule Trojan_BAT_SnakeLogger_ASI_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.ASI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 0a 02 28 ?? 00 00 06 0b 14 0c 00 73 ?? 00 00 0a 25 06 6f ?? 00 00 0a 00 25 07 6f ?? 00 00 0a 00 0c 08 6f ?? 00 00 0a 0d 09 03 16 03 8e 69 6f ?? 00 00 0a 13 ?? de 1b 09 2c 07 09 6f } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}