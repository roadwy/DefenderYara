
rule Trojan_Linux_CoinMiner_R_MTB{
	meta:
		description = "Trojan:Linux/CoinMiner.R!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 75 70 64 61 74 65 6d 69 6e 65 72 } //01 00  main.updateminer
		$a_01_1 = {63 72 79 70 74 6f 2f 63 75 72 76 65 32 35 35 31 39 } //01 00  crypto/curve25519
		$a_01_2 = {64 69 72 74 79 4c 6f 63 6b 65 64 } //00 00  dirtyLocked
	condition:
		any of ($a_*)
 
}