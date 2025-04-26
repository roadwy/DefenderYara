
rule TrojanDownloader_O97M_Obfuse_GR{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.GR,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_03_1 = {2e 52 75 6e 21 20 [0-14] 2e 56 61 6c 75 65 20 26 20 [0-14] 2e 43 6f 6e 74 72 6f 6c 73 28 30 29 2e 56 61 6c 75 65 2c } //2
		$a_03_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-14] 2e 43 6f 6e 74 72 6f 6c 73 28 31 29 2e 56 61 6c 75 65 29 } //1
		$a_03_3 = {3d 20 28 4e 6f 74 20 [0-11] 29 20 4f 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}