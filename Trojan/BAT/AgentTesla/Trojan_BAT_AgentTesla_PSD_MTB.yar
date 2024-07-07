
rule Trojan_BAT_AgentTesla_PSD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 c7 01 00 70 11 04 8c 0c 90 01 03 28 2a 90 01 03 28 1b 90 01 03 73 2b 90 01 03 25 72 f3 01 00 70 6f 2c 90 01 03 25 72 03 02 00 70 28 01 90 01 03 28 2a 90 01 03 6f 2d 90 01 03 25 17 6f 2e 90 01 03 25 17 6f 2f 90 01 03 25 16 6f 30 90 01 03 25 17 6f 31 90 01 03 28 32 90 01 03 26 28 01 90 01 03 14 1a 28 0a 90 01 03 26 16 2a 90 00 } //5
		$a_01_1 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_01_2 = {47 65 74 41 75 74 68 45 6e 63 72 79 70 74 65 64 43 6f 6e 74 65 6e 74 49 6e 66 6f } //1 GetAuthEncryptedContentInfo
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule Trojan_BAT_AgentTesla_PSD_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.PSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {7e 9c 00 00 04 d0 0e 90 01 03 28 0e 90 01 03 6f a3 90 01 03 2c 25 20 2e 17 c4 03 28 df 90 01 03 16 8d a7 90 01 03 28 a4 90 01 03 73 a5 90 01 03 7a 73 a6 90 01 03 80 9c 90 01 03 7e 9c 90 01 03 d0 0e 90 01 03 28 0e 90 01 03 14 6f a7 90 01 03 28 90 01 03 2b 0a 90 00 } //5
		$a_01_1 = {43 72 79 70 74 6f 53 74 72 65 61 6d 4d 6f 64 65 } //1 CryptoStreamMode
		$a_01_2 = {41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 4d 6f 64 65 } //1 AuthenticationMode
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}