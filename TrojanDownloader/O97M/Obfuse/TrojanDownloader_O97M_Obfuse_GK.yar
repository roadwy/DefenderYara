
rule TrojanDownloader_O97M_Obfuse_GK{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.GK,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_03_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-14] 20 2b 20 [0-14] 20 2b 20 [0-10] 29 2e 52 75 6e 24 20 [0-30] 20 2b 20 [0-12] 2c 20 76 62 48 69 64 65 } //1
		$a_01_2 = {2b 20 22 70 74 2e 53 22 20 2b 20 22 68 65 6c 6c 22 } //1 + "pt.S" + "hell"
		$a_01_3 = {2b 20 22 57 73 63 72 69 22 } //1 + "Wscri"
		$a_03_4 = {2a 20 43 53 74 72 28 [0-07] 20 2f 20 53 67 6e 28 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}