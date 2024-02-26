
rule Trojan_BAT_CoinMiner_MC_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 05 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 31 38 35 2e 31 37 32 2e 31 32 38 2e 31 31 } //01 00  http://185.172.128.11
		$a_01_1 = {65 6e 63 72 79 70 74 69 6f 6e 43 6f 6e 74 65 78 74 } //01 00  encryptionContext
		$a_01_2 = {47 65 74 43 6f 72 72 65 63 74 65 64 55 74 63 4e 6f 77 46 6f 72 45 6e 64 70 6f 69 6e 74 } //01 00  GetCorrectedUtcNowForEndpoint
		$a_01_3 = {44 69 73 61 62 6c 65 4c 6f 67 67 69 6e 67 } //01 00  DisableLogging
		$a_01_4 = {41 6c 6c 6f 77 41 75 74 6f 52 65 64 69 72 65 63 74 } //01 00  AllowAutoRedirect
		$a_01_5 = {67 65 74 5f 44 69 73 61 62 6c 65 48 6f 73 74 50 72 65 66 69 78 49 6e 6a 65 63 74 69 6f 6e } //00 00  get_DisableHostPrefixInjection
	condition:
		any of ($a_*)
 
}