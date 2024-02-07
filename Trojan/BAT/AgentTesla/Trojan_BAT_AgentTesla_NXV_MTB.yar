
rule Trojan_BAT_AgentTesla_NXV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 df a2 eb 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 1c 01 00 00 29 01 00 00 7c 03 00 00 ce 0d 00 00 8c 09 00 00 ad 00 00 00 11 05 00 00 32 } //01 00 
		$a_01_1 = {44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  DESCryptoServiceProvider
		$a_01_2 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  MD5CryptoServiceProvider
		$a_01_3 = {62 36 35 61 65 62 36 32 30 32 39 36 } //01 00  b65aeb620296
		$a_01_4 = {63 63 64 61 35 32 34 38 } //00 00  ccda5248
	condition:
		any of ($a_*)
 
}