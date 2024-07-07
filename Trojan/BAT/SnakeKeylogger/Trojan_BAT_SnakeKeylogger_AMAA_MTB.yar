
rule Trojan_BAT_SnakeKeylogger_AMAA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 02 28 90 01 01 00 00 06 75 90 01 01 00 00 1b 73 90 01 01 00 00 0a 0d 09 07 16 73 90 01 01 00 00 0a 13 04 11 04 08 6f 90 01 01 00 00 0a 08 13 05 dd 90 00 } //5
		$a_80_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
		$a_80_2 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //TripleDESCryptoServiceProvider  1
		$a_80_3 = {47 65 74 41 73 79 6e 63 } //GetAsync  1
		$a_80_4 = {48 74 74 70 43 6c 69 65 6e 74 } //HttpClient  1
	condition:
		((#a_03_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=9
 
}