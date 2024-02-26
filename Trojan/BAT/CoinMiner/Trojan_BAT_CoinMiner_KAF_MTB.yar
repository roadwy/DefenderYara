
rule Trojan_BAT_CoinMiner_KAF_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 35 00 34 00 2e 00 35 00 33 00 2e 00 31 00 36 00 30 00 2e 00 32 00 34 00 35 00 } //01 00  http://154.53.160.245
		$a_01_1 = {41 00 70 00 70 00 44 00 61 00 74 00 61 00 00 3f 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 } //01 00  AppData㼀\Microsoft\Wi
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}