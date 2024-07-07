
rule TrojanDownloader_O97M_Obfuse_BVK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BVK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } //1 ChrW(CLng((Not
		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 } //1 Debug.Print
		$a_01_2 = {3d 20 49 73 44 61 74 65 28 43 4c 6e 67 } //1 = IsDate(CLng
		$a_01_3 = {3d 20 56 70 71 37 39 30 30 72 4b 4a 2e 57 31 56 46 69 67 70 35 6d 77 71 6d 32 30 65 73 } //1 = Vpq7900rKJ.W1VFigp5mwqm20es
		$a_01_4 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 56 64 70 38 61 76 4c 74 41 34 } //1 = Len(Join(Array(Vdp8avLtA4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}