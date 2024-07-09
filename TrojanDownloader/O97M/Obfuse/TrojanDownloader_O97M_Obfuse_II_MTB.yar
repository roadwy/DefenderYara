
rule TrojanDownloader_O97M_Obfuse_II_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.II!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 20 31 20 54 6f 20 4c 65 6e 28 [0-40] 29 20 53 74 65 70 20 32 3a 20 4d 69 64 28 } //1
		$a_01_1 = {29 20 26 20 22 40 40 40 22 3a 20 4e 65 78 74 } //1 ) & "@@@": Next
		$a_01_2 = {2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c } //1 , Null, Null, Null
		$a_03_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-40] 2c 20 22 40 22 2c 20 22 22 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}