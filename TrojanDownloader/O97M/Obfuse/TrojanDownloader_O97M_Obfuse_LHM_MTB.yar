
rule TrojanDownloader_O97M_Obfuse_LHM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.LHM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {3d 20 53 68 65 65 74 73 28 22 90 02 08 22 29 2e 43 65 6c 6c 73 28 90 02 03 2c 20 90 02 02 29 2e 56 61 6c 75 65 90 00 } //1
		$a_03_1 = {3d 20 54 72 75 65 90 0c 02 00 4f 70 74 69 6f 6e 20 45 78 70 6c 69 63 69 74 90 0c 02 00 50 75 62 6c 69 63 90 00 } //1
		$a_01_2 = {43 61 6c 6c 20 49 6e 69 74 3a 20 43 61 6c 6c 20 } //1 Call Init: Call 
		$a_01_3 = {47 6f 54 6f 20 } //1 GoTo 
		$a_01_4 = {53 68 65 6c 6c 20 } //1 Shell 
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}