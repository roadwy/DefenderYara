
rule TrojanDownloader_O97M_Obfuse_PDA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 54 68 72 65 61 64 } //1 CreateThread
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_03_2 = {26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 [0-15] 2c 20 [0-15] 2c 20 32 29 29 29 } //1
		$a_03_3 = {3d 20 31 20 54 6f 20 4c 65 6e 28 [0-15] 29 20 53 74 65 70 20 32 } //1
		$a_03_4 = {28 30 2c 20 55 42 6f 75 6e 64 28 [0-15] 29 2c 20 26 48 31 30 30 30 2c 20 26 48 34 30 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}