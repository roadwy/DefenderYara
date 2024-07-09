
rule TrojanDownloader_O97M_Obfuse_EW{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EW,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_03_1 = {53 68 65 6c 6c [0-02] 20 5f } //1
		$a_03_2 = {49 6e 6c 69 6e 65 53 68 61 70 65 73 28 [0-17] 29 20 5f } //1
		$a_01_3 = {2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c 20 5f } //1 .AlternativeText, _
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}