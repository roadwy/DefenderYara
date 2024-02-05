
rule Trojan_BAT_AgentTesla_TO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.TO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 08 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 8e b7 17 33 1b 06 14 17 8d 90 01 03 01 0b 07 16 16 8d 90 01 03 01 a2 07 6f 90 01 03 0a 26 2b 09 06 14 14 6f 90 01 03 0a 26 2a 90 00 } //02 00 
		$a_80_1 = {47 65 74 50 61 72 61 6d 65 74 65 72 73 } //GetParameters  02 00 
		$a_80_2 = {49 6e 76 6f 6b 65 } //Invoke  02 00 
		$a_80_3 = {50 61 72 61 6d 65 74 65 72 69 7a 65 64 54 68 72 65 61 64 53 74 61 72 74 } //ParameterizedThreadStart  02 00 
		$a_80_4 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //FlushFinalBlock  02 00 
		$a_80_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  02 00 
		$a_80_6 = {43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //CryptoServiceProvider  02 00 
		$a_80_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  00 00 
	condition:
		any of ($a_*)
 
}