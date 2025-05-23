
rule HackTool_Linux_CryptoMiner_A{
	meta:
		description = "HackTool:Linux/CryptoMiner.A,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 0a 00 00 "
		
	strings :
		$a_00_0 = {78 00 6d 00 72 00 69 00 67 00 20 00 } //10 xmrig 
		$a_02_1 = {73 00 74 00 72 00 61 00 74 00 75 00 6d 00 [0-02] 2b 00 74 00 63 00 70 00 3a 00 2f 00 2f 00 } //1
		$a_02_2 = {73 00 74 00 72 00 61 00 74 00 75 00 6d 00 [0-02] 2b 00 73 00 73 00 6c 00 3a 00 2f 00 2f 00 } //1
		$a_00_3 = {2d 00 2d 00 64 00 6f 00 6e 00 61 00 74 00 65 00 2d 00 6c 00 65 00 76 00 65 00 6c 00 } //1 --donate-level
		$a_00_4 = {2d 00 2d 00 6d 00 61 00 78 00 2d 00 63 00 70 00 75 00 2d 00 75 00 73 00 61 00 67 00 65 00 } //1 --max-cpu-usage
		$a_00_5 = {2d 00 2d 00 6e 00 69 00 63 00 65 00 68 00 61 00 73 00 68 00 } //1 --nicehash
		$a_00_6 = {2d 00 2d 00 64 00 6f 00 6e 00 61 00 74 00 65 00 2d 00 6f 00 76 00 65 00 72 00 2d 00 70 00 72 00 6f 00 78 00 79 00 } //1 --donate-over-proxy
		$a_00_7 = {2d 00 2d 00 63 00 70 00 75 00 2d 00 61 00 66 00 66 00 69 00 6e 00 69 00 74 00 79 00 } //1 --cpu-affinity
		$a_00_8 = {2d 00 2d 00 63 00 70 00 75 00 2d 00 6d 00 61 00 78 00 2d 00 74 00 68 00 72 00 65 00 61 00 64 00 73 00 2d 00 68 00 69 00 6e 00 74 00 } //1 --cpu-max-threads-hint
		$a_00_9 = {2d 00 2d 00 63 00 70 00 75 00 2d 00 70 00 72 00 69 00 6f 00 72 00 69 00 74 00 79 00 } //1 --cpu-priority
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=11
 
}