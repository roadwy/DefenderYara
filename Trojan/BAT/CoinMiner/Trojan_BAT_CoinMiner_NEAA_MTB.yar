
rule Trojan_BAT_CoinMiner_NEAA_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {03 02 7b 37 00 00 04 61 0a 02 02 7b 37 00 00 04 1d 28 be 00 00 06 06 61 7d 37 00 00 04 06 2a } //02 00 
		$a_01_1 = {61 00 63 00 74 00 69 00 76 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 70 00 68 00 70 00 3f 00 63 00 6f 00 64 00 65 00 3d 00 } //02 00  activation.php?code=
		$a_01_2 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00 } //01 00  Mozilla/4.0
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_4 = {42 61 6e 6e 65 64 } //00 00  Banned
	condition:
		any of ($a_*)
 
}