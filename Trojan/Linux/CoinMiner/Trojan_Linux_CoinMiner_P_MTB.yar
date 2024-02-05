
rule Trojan_Linux_CoinMiner_P_MTB{
	meta:
		description = "Trojan:Linux/CoinMiner.P!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {63 75 72 6c 20 2d 6f 20 2f 74 6d 70 2f 2e 67 67 2f 74 6f 70 90 02 15 63 64 6e 2e 69 6e 74 65 72 61 6b 74 2e 6d 64 2f 74 6f 70 20 3e 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e 26 31 20 64 6f 6e 65 3b 90 00 } //02 00 
		$a_00_1 = {63 68 6d 6f 64 20 2b 78 20 2f 74 6d 70 2f 2e 67 67 2f 2a } //01 00 
		$a_00_2 = {63 64 20 2f 74 6d 70 2f 2e 67 67 20 26 26 20 72 6d 20 2d 72 66 20 74 6f 70 20 78 } //00 00 
	condition:
		any of ($a_*)
 
}