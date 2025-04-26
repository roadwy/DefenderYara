
rule Trojan_Win64_CoinMiner_GC_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 0d 00 00 "
		
	strings :
		$a_80_0 = {70 61 79 6c 6f 61 64 } //payload  1
		$a_80_1 = {3c 77 61 6c 6c 65 74 3e } //<wallet>  1
		$a_80_2 = {3c 63 6f 69 6e 3e } //<coin>  1
		$a_80_3 = {3c 73 74 6f 70 4d 69 6e 69 6e 67 3e } //<stopMining>  1
		$a_80_4 = {3c 4b 65 65 70 41 6c 69 76 65 3e } //<KeepAlive>  1
		$a_80_5 = {3c 49 73 43 6f 6e 6e 65 63 74 65 64 3e } //<IsConnected>  1
		$a_80_6 = {3c 69 6e 6a 65 63 74 69 6f 6e 3e } //<injection>  1
		$a_80_7 = {3c 52 65 67 65 78 3e } //<Regex>  1
		$a_80_8 = {43 6c 69 70 62 6f 61 72 64 } //Clipboard  1
		$a_80_9 = {43 50 55 4d 69 6e 69 6e 67 } //CPUMining  1
		$a_80_10 = {50 6f 77 65 72 73 68 65 6c 6c } //Powershell  1
		$a_80_11 = {47 72 61 62 62 65 72 } //Grabber  1
		$a_80_12 = {50 68 61 6e 74 6f 6d 5f 4d 69 6e 65 72 } //Phantom_Miner  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1) >=10
 
}