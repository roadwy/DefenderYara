
rule TrojanDownloader_O97M_Obfuse_FB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 90 02 01 28 90 02 10 20 2b 20 90 02 25 20 2b 20 90 00 } //2
		$a_03_1 = {43 61 6c 6c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 10 29 90 00 } //1
		$a_01_2 = {61 75 74 6f 6f 70 65 6e 28 20 5f } //1 autoopen( _
		$a_03_3 = {53 68 6f 77 57 69 6e 64 6f 77 90 02 01 20 3d 20 90 02 14 20 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}