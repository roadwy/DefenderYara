
rule TrojanDownloader_O97M_Obfuse_LHJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.LHJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 20 53 74 72 43 6f 6e 76 28 53 68 65 65 74 73 28 22 [0-10] 22 29 2e 43 65 6c 6c 73 28 [0-03] 2c 20 [0-02] 29 2e 56 61 6c 75 65 2c 20 [0-03] 29 } //1
		$a_03_1 = {3d 20 54 72 75 65 90 0c 02 00 4f 70 74 69 6f 6e 20 45 78 70 6c 69 63 69 74 90 0c 02 00 53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } //1
		$a_01_2 = {47 6f 54 6f 20 } //1 GoTo 
		$a_01_3 = {53 68 65 6c 6c 20 } //1 Shell 
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}