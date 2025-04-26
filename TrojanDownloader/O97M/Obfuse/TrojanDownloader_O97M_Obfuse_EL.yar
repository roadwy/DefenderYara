
rule TrojanDownloader_O97M_Obfuse_EL{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EL,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 20 [0-10] 2e [0-25] 20 2b 20 } //10
		$a_03_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-40] 29 } //1
		$a_03_2 = {53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 [0-14] 20 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=12
 
}