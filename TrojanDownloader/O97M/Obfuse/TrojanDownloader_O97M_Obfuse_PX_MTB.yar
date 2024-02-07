
rule TrojanDownloader_O97M_Obfuse_PX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 75 6e 63 74 69 6f 6e 20 73 75 63 6b 6d 79 64 69 63 6b 66 6f 72 6e 6f 72 65 61 73 6f 6e 31 31 28 29 } //01 00  Function suckmydickfornoreason11()
		$a_00_1 = {73 75 63 6b 6d 79 64 69 63 6b 66 6f 72 6e 6f 72 65 61 73 6f 6e 36 20 3d 20 22 68 22 } //01 00  suckmydickfornoreason6 = "h"
		$a_00_2 = {73 75 63 6b 6d 79 64 69 63 6b 66 6f 72 6e 6f 72 65 61 73 6f 6e 39 20 3d 20 22 70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f } //00 00  suckmydickfornoreason9 = "p://%20%20@j.mp/
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_PX_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 68 65 65 74 73 28 22 90 02 14 22 29 2e 43 65 6c 6c 73 28 90 02 10 29 2e 56 61 6c 75 65 2c 90 00 } //01 00 
		$a_03_1 = {2e 43 72 65 61 74 65 20 90 02 10 2c 20 90 02 10 2c 20 90 02 10 2c 20 4e 75 6c 6c 90 00 } //01 00 
		$a_03_2 = {3d 20 31 20 54 6f 20 4c 65 6e 28 90 02 20 29 20 53 74 65 70 20 32 90 00 } //01 00 
		$a_03_3 = {26 20 43 68 72 28 43 4c 6e 67 28 90 02 20 20 26 20 4d 69 64 28 90 02 20 2c 20 90 02 20 29 29 20 2d 20 90 02 02 29 90 02 02 4e 65 78 74 90 00 } //01 00 
		$a_01_4 = {3d 20 22 22 } //01 00  = ""
		$a_01_5 = {3d 20 43 68 72 28 30 } //00 00  = Chr(0
	condition:
		any of ($a_*)
 
}