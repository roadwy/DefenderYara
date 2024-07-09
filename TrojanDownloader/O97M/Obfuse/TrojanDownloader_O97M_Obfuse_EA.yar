
rule TrojanDownloader_O97M_Obfuse_EA{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EA,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 [0-10] 29 } //2
		$a_03_1 = {2e 43 72 65 61 74 65 ?? 28 [0-14] 2c 20 4e 75 6c 6c 2c 20 [0-14] 2c 20 [0-14] 29 } //1
		$a_03_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-14] 20 2b 20 22 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}