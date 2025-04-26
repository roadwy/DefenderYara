
rule Trojan_BAT_AgentTesla_LQL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LQL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 21 02 08 09 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 13 05 07 06 11 05 28 ?? ?? ?? 0a 9c 11 04 17 58 13 04 11 04 17 32 da } //1
		$a_01_1 = {42 53 54 52 4d 61 72 73 68 61 6c 65 72 } //1 BSTRMarshaler
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_LQL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.LQL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {0a 1f 20 06 6f ?? ?? ?? 0a 8e 69 1f 20 59 6f ?? ?? ?? 0a 13 04 06 16 6a 6f ?? ?? ?? 0a 06 11 04 16 11 04 8e 69 6f } //1
		$a_03_1 = {0a 1f 10 6a 59 17 6a 58 d4 8d ?? ?? ?? 01 13 07 11 06 11 07 16 11 07 8e 69 6f ?? ?? ?? 0a 8d ?? ?? ?? 01 13 08 11 07 16 11 08 16 11 08 8e 69 28 ?? ?? ?? 0a 11 08 13 09 } //1
		$a_01_2 = {41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 AesCryptoServiceProvider
		$a_01_3 = {41 72 65 45 71 75 61 6c } //1 AreEqual
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}