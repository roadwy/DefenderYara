
rule TrojanDownloader_O97M_Obfuse_PBJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PBJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 } //1 = Environ("AppData")
		$a_03_1 = {2b 20 43 68 72 28 33 34 29 20 2b 20 [0-20] 20 2b 20 43 68 72 28 33 34 29 } //1
		$a_03_2 = {2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 [0-20] 2c 20 32 2c 20 54 72 75 65 29 } //1
		$a_03_3 = {43 61 6c 6c 20 53 68 65 6c 6c 28 [0-20] 20 26 20 [0-20] 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*2) >=5
 
}