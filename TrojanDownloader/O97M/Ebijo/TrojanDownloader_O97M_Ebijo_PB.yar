
rule TrojanDownloader_O97M_Ebijo_PB{
	meta:
		description = "TrojanDownloader:O97M/Ebijo.PB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {49 6e 74 65 72 61 63 74 69 6f 6e 20 5f 0d 0a 2e 53 68 65 6c 6c 28 [0-20] 29 2c 20 [0-0a] 29 } //1
		$a_01_1 = {46 75 6e 63 74 69 6f 6e 20 45 62 69 6a 6f 28 29 } //1 Function Ebijo()
		$a_03_2 = {53 65 74 20 [0-0a] 20 3d 20 [0-0a] 2e 53 68 61 70 65 73 28 [0-40] 29 2e 54 65 78 74 46 72 61 6d 65 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}