
rule TrojanDownloader_O97M_Obfuse_BLK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BLK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } //1 ChrW(CLng((Not
		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 } //1 Debug.Print
		$a_01_2 = {3d 20 43 61 75 54 74 73 32 73 2e 56 53 76 77 63 33 4c } //1 = CauTts2s.VSvwc3L
		$a_01_3 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 4a 44 4c 33 77 68 6d 63 } //1 = Len(Join(Array(JDL3whmc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_BLK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BLK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } //1 ChrW(CLng((Not
		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 } //1 Debug.Print
		$a_01_2 = {3d 20 52 43 75 62 5f 4d 68 68 5f 78 59 41 6c 5f 37 77 54 2e 44 48 74 45 6f 6f 33 4a } //1 = RCub_Mhh_xYAl_7wT.DHtEoo3J
		$a_01_3 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 67 6d 42 4a 70 5f 32 30 73 } //1 = Len(Join(Array(gmBJp_20s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_BLK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BLK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } //1 ChrW(CLng((Not
		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 } //1 Debug.Print
		$a_01_2 = {3d 20 57 51 57 56 43 5f 44 47 52 34 5f 77 56 30 39 5f 64 75 65 2e 4f 67 42 30 5f 63 31 66 5f 53 55 51 } //1 = WQWVC_DGR4_wV09_due.OgB0_c1f_SUQ
		$a_01_3 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 50 50 45 4f 61 68 6d 4c 68 66 } //1 = Len(Join(Array(PPEOahmLhf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_BLK_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BLK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } //1 ChrW(CLng((Not
		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 } //1 Debug.Print
		$a_01_2 = {3d 20 62 67 74 4a 6a 5f 55 69 48 37 5f 6a 6d 50 2e 50 73 7a 58 73 5f 47 57 6b 4e } //1 = bgtJj_UiH7_jmP.PszXs_GWkN
		$a_01_3 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 45 45 62 70 6d 5f 44 33 71 5f 32 5a 59 36 5f 57 41 38 } //1 = Len(Join(Array(EEbpm_D3q_2ZY6_WA8
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_BLK_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BLK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } //1 ChrW(CLng((Not
		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 } //1 Debug.Print
		$a_01_2 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } //1 = Join(Array(ChrW(CLng((Not
		$a_01_3 = {3d 20 48 67 59 6c 5f 44 76 35 5f 4f 61 69 5f 37 33 53 2e 48 6e 67 57 6e 71 4b 57 53 57 39 } //1 = HgYl_Dv5_Oai_73S.HngWnqKWSW9
		$a_01_4 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 44 6e 6b 69 33 65 78 4f 75 46 67 4c 6d 6c } //1 = Len(Join(Array(Dnki3exOuFgLml
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_BLK_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BLK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 66 6a 6b 65 72 6f 6f 6f 73 2c 20 66 67 66 6a 68 66 67 66 67 2c 20 22 22 2c 20 22 22 2c 20 30 } //1 .ShellExecute "P" + fjkerooos, fgfjhfgfg, "", "", 0
		$a_01_1 = {3d 20 78 63 6d 45 6b 56 77 52 64 59 73 47 44 53 55 4d 28 62 46 42 71 6f 73 66 54 73 6f 54 45 2c 20 74 37 67 68 30 2c 20 67 74 6d 73 64 29 } //1 = xcmEkVwRdYsGDSUM(bFBqosfTsoTE, t7gh0, gtmsd)
		$a_01_2 = {3d 20 48 4c 45 57 48 57 65 44 6e 44 68 50 53 50 65 6f 28 58 54 44 44 6d 77 78 52 44 51 4c 6b 2c 20 74 37 67 68 30 2c 20 67 74 6d 73 64 29 } //1 = HLEWHWeDnDhPSPeo(XTDDmwxRDQLk, t7gh0, gtmsd)
		$a_01_3 = {3d 20 70 54 5a 63 4d 58 65 69 6a 78 62 5a 54 5a 51 76 28 4a 66 79 58 7a 63 43 6c 59 42 50 56 2c 20 74 37 67 68 30 2c 20 67 74 6d 73 64 29 } //1 = pTZcMXeijxbZTZQv(JfyXzcClYBPV, t7gh0, gtmsd)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}