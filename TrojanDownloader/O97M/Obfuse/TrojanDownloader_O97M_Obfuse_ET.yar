
rule TrojanDownloader_O97M_Obfuse_ET{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.ET,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {47 65 74 4f 62 6a 65 63 74 28 28 [0-10] 20 2b 20 22 77 69 6e 6d 67 6d 74 73 3a 57 69 22 20 2b 20 [0-10] 20 2b 20 22 6e 33 32 5f 50 22 20 2b 20 22 72 6f 63 65 73 73 22 29 29 2e 43 72 65 61 74 65 28 28 [0-18] 20 2b 20 [0-20] 20 2b 20 } //2
		$a_03_1 = {53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 [0-14] 20 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}