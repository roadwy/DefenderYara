
rule Trojan_BAT_CoinMiner_NL_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_80_0 = {52 6f 67 75 65 4d 61 72 6b 65 74 5c 50 72 6f 64 75 63 74 73 5c 52 6f 67 75 65 20 4d 69 6e 65 72 20 56 32 5c 52 65 76 69 65 77 20 42 61 63 6b 75 70 5c 45 72 20 6d 69 6e 61 74 6f 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4f 6d 65 67 61 4d 69 6e 65 72 2e 70 64 62 } //RogueMarket\Products\Rogue Miner V2\Review Backup\Er minator\obj\Release\OmegaMiner.pdb  4
		$a_80_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //SOFTWARE\Microsoft\Windows\CurrentVersion\Run  1
		$a_80_2 = {2d 42 20 2d 2d 64 6f 6e 61 74 65 2d 6c 65 76 65 6c 20 31 } //-B --donate-level 1  1
		$a_80_3 = {63 6f 69 6e 20 6d 6f 6e 65 72 6f } //coin monero  1
		$a_80_4 = {41 63 74 69 76 65 20 4d 61 78 20 43 50 55 } //Active Max CPU  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=8
 
}