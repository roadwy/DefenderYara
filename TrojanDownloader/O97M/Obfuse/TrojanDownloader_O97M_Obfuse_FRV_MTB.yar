
rule TrojanDownloader_O97M_Obfuse_FRV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FRV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 6b 2e 63 6c 6f 6e 65 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 } //1 Shell k.clone.ControlTipText
		$a_01_1 = {6b 2e 6f 70 65 6e 65 72 2e 47 72 6f 75 70 4e 61 6d 65 } //1 k.opener.GroupName
		$a_03_2 = {53 75 62 20 5f 90 0c 02 00 41 75 74 6f 5f 63 6c 6f 73 65 28 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Obfuse_FRV_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FRV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 5f 5f 5f 76 20 3d 20 43 68 72 28 64 73 20 2d 20 39 39 29 } //1 b___v = Chr(ds - 99)
		$a_01_1 = {62 5f 5f 5f 76 28 31 38 36 29 20 26 20 62 5f 5f 5f 76 28 31 38 32 29 20 26 20 62 5f 5f 5f 76 28 31 36 36 29 20 26 20 62 5f 5f 5f 76 28 32 31 33 29 20 26 20 62 5f 5f 5f 76 28 32 30 34 29 20 26 20 62 5f 5f 5f 76 28 32 31 31 29 20 26 20 62 5f 5f 5f 76 28 31 38 33 29 20 26 20 62 5f 5f 5f 76 28 31 34 35 29 20 26 20 62 5f 5f 5f 76 28 32 31 34 29 20 26 20 62 5f 5f 5f 76 28 31 37 31 29 20 26 20 62 5f 5f 5f 76 28 31 36 38 29 20 26 20 62 5f 5f 5f 76 28 32 30 37 29 20 26 20 62 5f 5f 5f 76 28 31 37 35 29 } //1 b___v(186) & b___v(182) & b___v(166) & b___v(213) & b___v(204) & b___v(211) & b___v(183) & b___v(145) & b___v(214) & b___v(171) & b___v(168) & b___v(207) & b___v(175)
		$a_01_2 = {3d 20 22 69 6f 73 61 64 66 6f 64 73 69 20 35 36 34 36 20 64 73 61 66 64 73 79 61 67 66 38 20 66 69 73 64 75 65 72 77 39 38 22 } //1 = "iosadfodsi 5646 dsafdsyagf8 fisduerw98"
		$a_03_3 = {53 75 62 20 [0-19] 28 29 0d 0a 68 68 66 67 67 68 67 66 66 20 3d 20 33 0d 0a 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}