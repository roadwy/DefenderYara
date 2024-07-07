
rule VirTool_BAT_SilentCryptoMiner{
	meta:
		description = "VirTool:BAT/SilentCryptoMiner,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {52 65 6c 65 61 73 65 5c 53 69 6c 65 6e 74 20 43 72 79 70 74 6f 20 4d 69 6e 65 72 20 42 75 69 6c 64 65 72 2e 70 64 62 } //2 Release\Silent Crypto Miner Builder.pdb
		$a_01_1 = {53 69 6c 65 6e 74 43 72 79 70 74 6f 4d 69 6e 65 72 2e 41 6c 67 6f 72 69 74 68 6d 53 65 6c 65 63 74 69 6f 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 SilentCryptoMiner.AlgorithmSelection.resources
		$a_01_2 = {41 00 64 00 64 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 50 00 61 00 74 00 68 00 20 00 40 00 28 00 24 00 65 00 6e 00 76 00 3a 00 55 00 73 00 65 00 72 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 } //1 Add-MpPreference -ExclusionPath @($env:UserProfile
		$a_01_3 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 61 00 20 00 63 00 72 00 79 00 70 00 74 00 6f 00 63 00 75 00 72 00 72 00 65 00 6e 00 63 00 79 00 20 00 28 00 61 00 6c 00 67 00 6f 00 72 00 69 00 74 00 68 00 6d 00 29 00 20 00 74 00 6f 00 20 00 6d 00 69 00 6e 00 65 00 } //1 Select a cryptocurrency (algorithm) to mine
		$a_01_4 = {44 00 65 00 66 00 52 00 6f 00 6f 00 74 00 6b 00 69 00 74 00 } //1 DefRootkit
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}