
rule Trojan_BAT_AgentTesla_GCD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 1b 7e 18 01 00 04 06 7e 18 01 00 04 06 91 06 61 20 aa 00 00 00 61 d2 9c 06 17 58 0a 06 7e 18 01 00 04 8e 69 fe 04 2d d9 2a } //01 00 
		$a_01_1 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  TripleDESCryptoServiceProvider
		$a_01_2 = {42 43 72 79 70 74 44 65 63 72 79 70 74 } //f6 ff  BCryptDecrypt
		$a_01_3 = {43 72 79 70 74 6f 4c 69 62 72 61 72 79 2e 64 6c 6c } //00 00  CryptoLibrary.dll
	condition:
		any of ($a_*)
 
}