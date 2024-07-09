
rule PUA_Linux_CoinMiner_K{
	meta:
		description = "PUA:Linux/CoinMiner.K,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {70 72 6f 63 2f 63 70 75 69 6e 66 6f } //1 proc/cpuinfo
		$a_00_1 = {6d 61 78 2d 63 70 75 2d 75 73 61 67 65 } //1 max-cpu-usage
		$a_00_2 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f } //2 stratum+tcp://
		$a_00_3 = {6e 69 63 65 68 61 73 68 2e 63 6f 6d } //2 nicehash.com
		$a_02_4 = {6d 69 6e 65 78 6d 72 2e [0-03] 3a } //2
		$a_01_5 = {54 72 79 20 60 6d 69 6e 65 72 64 20 2d 2d 68 65 6c 70 } //2 Try `minerd --help
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_02_4  & 1)*2+(#a_01_5  & 1)*2) >=4
 
}