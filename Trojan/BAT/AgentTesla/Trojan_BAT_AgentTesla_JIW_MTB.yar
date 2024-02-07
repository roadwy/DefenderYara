
rule Trojan_BAT_AgentTesla_JIW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JIW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 02 16 02 8e b7 6f 90 01 03 0a 13 90 01 01 72 90 02 03 70 90 00 } //01 00 
		$a_01_1 = {4c 00 6f 00 61 00 64 00 00 15 45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 00 0d 49 00 6e 00 76 00 6f 00 6b 00 65 } //01 00 
		$a_81_2 = {41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  AesCryptoServiceProvider
		$a_81_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_5 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //01 00  WriteAllBytes
		$a_81_6 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //00 00  GetObjectValue
	condition:
		any of ($a_*)
 
}