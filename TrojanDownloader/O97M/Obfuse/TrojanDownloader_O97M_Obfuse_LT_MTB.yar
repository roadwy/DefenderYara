
rule TrojanDownloader_O97M_Obfuse_LT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.LT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-14] 28 22 3a 35 33 77 3a 35 33 69 3a 35 33 6e 6d 3a 35 33 67 6d 74 73 3a 57 3a 35 33 69 6e 3a 35 33 33 3a 35 33 32 5f 3a 35 33 50 72 6f 3a 35 33 63 65 3a 35 33 73 3a 35 33 73 22 29 29 2e 43 72 65 61 74 65 28 [0-38] 2c } //1
		$a_03_1 = {3d 20 52 65 70 6c 61 63 65 28 [0-14] 2c 20 52 65 70 6c 61 63 65 28 22 3a 75 71 77 68 64 73 61 64 35 75 71 77 68 64 73 61 64 33 22 2c 20 22 75 71 77 68 64 73 61 64 22 2c 20 22 22 29 2c 20 22 22 29 } //1
		$a_01_2 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d } //1 .ShowWindow =
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}