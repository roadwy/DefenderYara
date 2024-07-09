
rule TrojanDownloader_O97M_Obfuse_NW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.NW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {48 79 70 65 72 58 20 3d 20 48 79 70 65 72 58 20 2b 20 30 2e } //1 HyperX = HyperX + 0.
		$a_01_1 = {4e 47 70 6f 77 65 72 20 3d 20 4e 47 70 6f 77 65 72 20 2d 20 30 2e } //1 NGpower = NGpower - 0.
		$a_03_2 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 63 3a 5c [0-40] 2e 62 61 74 22 2c 20 54 72 75 65 29 } //1
		$a_01_3 = {2e 57 72 69 74 65 4c 69 6e 65 20 28 22 70 6f 77 5e 22 29 } //1 .WriteLine ("pow^")
		$a_01_4 = {2e 57 72 69 74 65 4c 69 6e 65 20 28 22 65 5e 22 29 } //1 .WriteLine ("e^")
		$a_01_5 = {2e 57 72 69 74 65 4c 69 6e 65 20 28 22 78 5e 22 29 } //1 .WriteLine ("x^")
		$a_01_6 = {2a 20 4c 69 74 65 29 } //1 * Lite)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}