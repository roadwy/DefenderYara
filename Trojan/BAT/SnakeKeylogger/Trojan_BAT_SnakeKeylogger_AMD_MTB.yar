
rule Trojan_BAT_SnakeKeylogger_AMD_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 09 11 04 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 0a 06 11 05 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a 06 6f ?? 00 00 0a 10 00 de 0e } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}