
rule TrojanDownloader_O97M_Obfuse_APD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.APD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 63 68 72 28 35 30 29 2b 63 68 72 28 34 38 29 2b 63 68 72 28 34 38 29 [0-03] 77 73 68 73 68 65 6c 6c } //1
		$a_03_1 = {73 70 65 63 69 61 6c 70 61 74 68 3d 77 73 68 73 68 65 6c 6c 2e 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 28 22 [0-0a] 22 29 64 69 6d 64 69 6d } //1
		$a_03_2 = {3d 73 70 65 63 69 61 6c 70 61 74 68 2b 28 22 [0-0a] 2e 22 29 2e 6f 70 65 6e 22 67 65 74 22 2c 28 22 68 3a 2f 2f 6a 2d 68 6c 67 2e 6d 2f 62 2f 6d 62 6c 68 64 6c 2e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}