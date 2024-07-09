
rule Trojan_BAT_AgentTesla_JTO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JTO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 6f ?? ?? ?? 0a 73 ?? ?? ?? 0a 0c 08 07 6f ?? ?? ?? 0a 08 04 6f ?? ?? ?? 0a 08 05 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 02 16 02 8e 69 6f } //1
		$a_81_1 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 MD5CryptoServiceProvider
		$a_81_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_3 = {76 65 63 72 79 70 74 } //1 vecrypt
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}