
rule Trojan_BAT_CoinMiner_GCD_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.GCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 5f 4c 4f 56 45 5f 48 45 4e 54 41 49 } //1 I_LOVE_HENTAI
		$a_01_1 = {74 78 4c 4c 76 44 52 4e 6a 45 33 37 72 67 4f 54 50 66 } //1 txLLvDRNjE37rgOTPf
		$a_01_2 = {66 35 50 55 65 51 79 62 43 4f 47 52 72 41 6e 63 51 53 } //1 f5PUeQybCOGRrAncQS
		$a_01_3 = {62 45 55 66 4d 6a 70 34 6e 76 68 4c 37 58 69 32 4d 57 } //1 bEUfMjp4nvhL7Xi2MW
		$a_01_4 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_01_5 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}