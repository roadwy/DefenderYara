
rule Trojan_Win64_CoinMiner_PABA_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.PABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8d 4a 14 0f b7 02 66 2d 1b 4a 66 25 ff 00 66 89 02 48 83 c2 02 48 39 ca 75 e9 } //01 00 
		$a_01_1 = {66 2d 71 0a 66 25 ff 00 66 89 02 48 83 c2 02 48 39 ca 75 e9 } //00 00 
	condition:
		any of ($a_*)
 
}