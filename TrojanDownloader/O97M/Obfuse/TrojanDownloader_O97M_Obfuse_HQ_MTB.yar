
rule TrojanDownloader_O97M_Obfuse_HQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_03_1 = {53 65 74 20 [0-12] 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-10] 29 } //1
		$a_03_2 = {29 2e 52 75 6e 21 20 [0-14] 2c 20 32 20 2b } //1
		$a_01_3 = {2e 43 6f 6e 74 72 6f 6c 73 } //1 .Controls
		$a_01_4 = {2e 56 61 6c 75 65 } //1 .Value
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}