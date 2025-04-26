
rule TrojanDownloader_O97M_Obfuse_GC{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.GC,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_03_1 = {2e 52 75 6e 40 20 [0-12] 20 5f } //2
		$a_01_2 = {3d 20 56 42 41 2e 20 5f } //1 = VBA. _
		$a_03_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-12] 2e 54 65 78 74 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}