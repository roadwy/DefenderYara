
rule TrojanDownloader_O97M_Obfuse_FJ{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FJ,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-14] 28 [0-28] 29 29 2e 52 75 6e 20 [0-14] 28 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 [0-07] 29 2e 52 61 6e 67 65 28 [0-07] 29 2e 56 61 6c 75 65 29 2c 20 56 61 6c 28 [0-04] 29 [0-15] 20 54 72 75 65 } //2
		$a_03_1 = {26 20 52 69 67 68 74 28 4c 65 66 74 28 [0-15] 2c 20 [0-14] 20 2b 20 28 } //1
		$a_03_2 = {20 2a 20 49 6e 74 28 [0-02] 20 2f 20 [0-02] 20 2d 20 [0-02] 29 20 2d 20 49 6e 74 28 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}