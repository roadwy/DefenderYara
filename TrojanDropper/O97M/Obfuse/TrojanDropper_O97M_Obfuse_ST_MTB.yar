
rule TrojanDropper_O97M_Obfuse_ST_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.ST!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {4d 61 6b 65 53 75 72 65 44 69 72 65 63 74 6f 72 79 50 61 74 68 45 78 69 73 74 73 } //1 MakeSureDirectoryPathExists
		$a_03_1 = {20 3d 20 73 74 72 50 61 72 68 20 26 20 22 90 02 0a 22 20 26 20 22 2e 6a 73 65 22 90 00 } //1
		$a_03_2 = {20 3d 20 22 63 3a 5c 52 65 77 69 5f 43 6f 6f 6c 5c 90 02 0a 2e 63 6d 64 22 90 00 } //1
		$a_03_3 = {20 3d 20 22 63 3a 5c 55 73 65 72 5f 46 6f 74 6f 5c 90 02 0a 2e 62 61 74 22 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}