
rule Trojan_Win32_AgentTesla_E_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.E!MTB,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  DESCryptoServiceProvider
		$a_01_1 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //01 00  System.Security.Cryptography
		$a_01_2 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  MD5CryptoServiceProvider
		$a_01_3 = {43 69 70 68 65 72 4d 6f 64 65 } //01 00  CipherMode
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_5 = {49 43 72 79 70 74 6f 54 72 61 6e 73 66 6f 72 6d } //01 00  ICryptoTransform
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_7 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_8 = {43 00 36 00 4b 00 43 00 68 00 79 00 6e 00 71 00 7a 00 69 00 47 00 59 00 64 00 6b 00 70 00 48 00 54 00 36 00 36 00 50 00 43 00 75 00 4c 00 55 00 50 00 30 00 53 00 32 00 4d 00 57 00 63 00 37 00 4a 00 } //00 00  C6KChynqziGYdkpHT66PCuLUP0S2MWc7J
	condition:
		any of ($a_*)
 
}