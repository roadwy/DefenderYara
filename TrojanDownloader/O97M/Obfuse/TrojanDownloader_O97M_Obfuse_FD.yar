
rule TrojanDownloader_O97M_Obfuse_FD{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FD,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-10] 2e 20 5f } //2
		$a_01_1 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_03_2 = {54 65 78 74 29 2e 52 75 6e [0-01] 28 20 5f } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}