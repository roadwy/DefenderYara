
rule TrojanDownloader_O97M_Obfuse_DF{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DF,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 72 75 6e 28 [0-10] 29 } //1
		$a_03_1 = {3d 20 56 42 41 2e 53 68 65 6c 6c 28 [0-10] 2c 20 30 29 } //1
		$a_01_2 = {43 61 6c 6c 20 7a } //1 Call z
		$a_01_3 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 43 6c 6f 73 65 28 29 } //1 Sub Document_Close()
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}