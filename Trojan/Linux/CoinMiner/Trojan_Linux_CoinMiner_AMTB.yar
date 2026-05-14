
rule Trojan_Linux_CoinMiner_AMTB{
	meta:
		description = "Trojan:Linux/CoinMiner!AMTB,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_80_0 = {38 32 2e 32 32 31 2e 31 30 33 2e 32 34 34 } //82.221.103.244  2
		$a_80_1 = {72 6f 75 74 65 72 2e 62 69 74 74 6f 72 72 65 6e 74 2e 63 6f 6d } //router.bittorrent.com  2
		$a_80_2 = {72 65 76 65 72 73 65 53 68 65 6c 6c } //reverseShell  1
		$a_80_3 = {72 73 61 45 6e 63 72 79 70 74 69 6f 6e } //rsaEncryption  1
		$a_80_4 = {6d 69 6e 65 72 } //miner  1
		$a_80_5 = {77 61 6c 6c 65 74 } //wallet  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=7
 
}