
rule Trojan_Linux_CoinMiner_C12{
	meta:
		description = "Trojan:Linux/CoinMiner.C12,SIGNATURE_TYPE_ELFHSTR_EXT,0a 00 0a 00 0f 00 00 "
		
	strings :
		$a_80_0 = {78 6d 72 69 67 } //xmrig  2
		$a_80_1 = {73 74 72 61 74 75 6d 2b 73 73 6c } //stratum+ssl  2
		$a_80_2 = {72 61 6e 64 6f 6d 78 } //randomx  2
		$a_80_3 = {4d 6f 6e 65 72 6f } //Monero  2
		$a_80_4 = {4b 65 76 61 63 6f 69 6e } //Kevacoin  2
		$a_80_5 = {52 61 76 65 6e 63 6f 69 6e } //Ravencoin  2
		$a_80_6 = {77 6f 77 6e 65 72 6f } //wownero  2
		$a_80_7 = {6d 65 6d 6f 72 79 2d 70 6f 6f 6c } //memory-pool  2
		$a_80_8 = {68 75 67 65 2d 70 61 67 65 73 } //huge-pages  2
		$a_80_9 = {70 6f 6f 6c 20 61 64 64 72 65 73 73 } //pool address  2
		$a_80_10 = {73 6f 63 6b 73 35 3a 2f 2f } //socks5://  2
		$a_80_11 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f } //stratum+tcp://  2
		$a_80_12 = {2f 6e 72 5f 68 75 67 65 70 61 67 65 73 } ///nr_hugepages  2
		$a_80_13 = {63 72 79 70 74 6f 6e 69 67 68 74 } //cryptonight  2
		$a_80_14 = {6d 69 6e 69 6e 67 2e 61 75 74 68 6f 72 69 7a 65 } //mining.authorize  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2+(#a_80_8  & 1)*2+(#a_80_9  & 1)*2+(#a_80_10  & 1)*2+(#a_80_11  & 1)*2+(#a_80_12  & 1)*2+(#a_80_13  & 1)*2+(#a_80_14  & 1)*2) >=10
 
}