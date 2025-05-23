
rule TrojanDownloader_O97M_Obfuse_RVAB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVAB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 57 53 43 72 69 70 74 2e 73 68 65 6c 6c 22 } //1 = "WSCript.shell"
		$a_01_1 = {68 66 66 20 3d 20 43 68 72 28 62 67 66 62 67 20 2d 20 31 31 34 29 } //1 hff = Chr(bgfbg - 114)
		$a_01_2 = {73 72 6f 77 20 3d 20 68 66 66 28 32 31 33 29 20 26 20 68 66 66 28 31 39 31 29 20 26 20 68 66 66 28 32 31 34 29 20 26 20 68 66 66 28 31 34 36 29 20 26 20 68 66 66 28 31 36 31 29 20 26 20 68 66 66 28 32 31 33 29 20 26 20 68 66 66 28 31 34 36 29 20 26 20 68 66 66 28 32 32 36 29 20 26 20 68 66 66 28 32 32 35 29 20 26 20 68 66 66 28 32 30 38 29 20 26 20 68 66 66 28 32 30 31 29 20 26 20 68 66 66 28 32 30 38 29 20 26 20 68 66 66 28 32 31 35 29 20 26 20 68 66 66 28 31 39 36 29 20 26 20 68 66 66 28 32 32 39 29 20 26 20 68 66 66 28 32 30 38 29 } //1 srow = hff(213) & hff(191) & hff(214) & hff(146) & hff(161) & hff(213) & hff(146) & hff(226) & hff(225) & hff(208) & hff(201) & hff(208) & hff(215) & hff(196) & hff(229) & hff(208)
		$a_03_3 = {2e 52 75 6e 28 [0-1e] 2c 20 [0-1e] 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_01_4 = {64 6f 63 41 63 74 69 76 65 2e 52 61 6e 67 65 28 53 74 61 72 74 3a 3d 64 6f 63 41 63 74 69 76 65 2e 57 6f 72 64 73 28 31 29 2e 53 74 61 72 74 2c 20 5f } //1 docActive.Range(Start:=docActive.Words(1).Start, _
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}