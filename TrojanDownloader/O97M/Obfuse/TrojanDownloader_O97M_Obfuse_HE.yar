
rule TrojanDownloader_O97M_Obfuse_HE{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HE,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_03_1 = {56 42 41 2e 47 65 74 4f 62 6a 65 63 74 28 [0-24] 2e 54 65 78 74 29 2e 52 75 6e 21 20 [0-16] 2c 20 30 20 2b 20 } //1
		$a_01_2 = {2e 43 6f 6e 74 72 6f 6c 73 } //1 .Controls
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}