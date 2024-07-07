
rule TrojanDownloader_O97M_Obfuse_DPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 63 68 72 28 35 30 29 2b 63 68 72 28 34 38 29 2b 63 68 72 28 34 38 29 64 69 6d 77 73 68 73 68 65 6c 6c 61 73 6f 62 6a 65 63 74 64 69 6d 67 65 74 75 73 65 72 64 65 73 6b 74 6f 70 } //1 =chr(50)+chr(48)+chr(48)dimwshshellasobjectdimgetuserdesktop
		$a_03_1 = {3d 6f 62 6a 77 73 68 73 68 65 6c 6c 2e 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 28 22 90 02 0f 22 29 64 69 6d 90 00 } //1
		$a_03_2 = {3d 67 65 74 75 73 65 72 64 65 73 6b 74 6f 70 2b 90 02 0f 28 22 90 02 0f 6e 6e 22 29 90 02 c8 2e 6f 70 65 6e 22 67 65 74 22 2c 90 1b 00 28 90 00 } //1
		$a_03_3 = {26 63 68 72 28 61 73 63 28 6d 69 64 28 90 02 c8 2c 90 02 c8 2c 31 29 29 2d 31 33 29 6e 65 78 74 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}