
rule Trojan_BAT_Discord_M_MTB{
	meta:
		description = "Trojan:BAT/Discord.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 75 4d 69 6e 65 72 2e 70 64 62 } //01 00  ZuMiner.pdb
		$a_01_1 = {52 61 6e 64 6f 6d 57 61 6c 6c 65 74 } //01 00  RandomWallet
		$a_01_2 = {45 00 78 00 6f 00 64 00 75 00 73 00 5c 00 65 00 78 00 6f 00 64 00 75 00 73 00 2e 00 77 00 61 00 6c 00 6c 00 65 00 74 00 } //01 00  Exodus\exodus.wallet
		$a_01_3 = {44 00 69 00 73 00 63 00 6f 00 72 00 64 00 5c 00 54 00 6f 00 6b 00 65 00 6e 00 73 00 2e 00 74 00 78 00 74 00 } //01 00  Discord\Tokens.txt
		$a_01_4 = {77 00 61 00 6c 00 6c 00 65 00 74 00 2e 00 69 00 64 00 2e 00 74 00 78 00 74 00 } //00 00  wallet.id.txt
	condition:
		any of ($a_*)
 
}