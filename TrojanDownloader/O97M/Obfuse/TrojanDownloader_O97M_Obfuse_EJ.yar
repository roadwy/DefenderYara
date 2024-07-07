
rule TrojanDownloader_O97M_Obfuse_EJ{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EJ,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_03_1 = {47 65 74 4f 62 6a 65 63 74 28 22 57 69 6e 6d 67 6d 74 73 3a 22 29 2e 47 65 74 28 53 74 72 52 65 76 65 72 73 65 28 22 90 02 15 22 29 29 2e 43 72 65 61 74 65 20 90 02 06 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 70 69 64 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}