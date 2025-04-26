
rule TrojanDownloader_O97M_Dridex_BSK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.BSK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 11 00 00 "
		
	strings :
		$a_01_0 = {46 69 6e 64 57 69 6e 64 6f 77 45 78 41 } //1 FindWindowExA
		$a_01_1 = {75 73 65 72 33 32 2e 64 6c 6c } //1 user32.dll
		$a_01_2 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } //1 ChrW(CLng((Not
		$a_01_3 = {44 65 62 75 67 2e 50 72 69 6e 74 } //1 Debug.Print
		$a_01_4 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 43 68 72 28 43 4c 6e 67 } //1 = Join(Array(Chr(CLng
		$a_01_5 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 77 54 76 47 72 5f 31 49 32 56 5f 4b 6f 69 47 } //1 = Len(Join(Array(wTvGr_1I2V_KoiG
		$a_01_6 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 59 51 78 45 79 75 4f 30 77 44 4f 69 53 4f 34 } //1 = Len(Join(Array(YQxEyuO0wDOiSO4
		$a_01_7 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 66 6c 50 70 47 5f 75 67 38 } //1 = Len(Join(Array(flPpG_ug8
		$a_01_8 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 22 78 4e 64 6a 63 5f 4f 5a 56 } //1 = Len(Join(Array("xNdjc_OZV
		$a_01_9 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 22 47 76 71 4c 35 4b 31 45 66 47 71 55 4b 5a 4b 65 71 34 6a 76 6c 43 70 6e 4f 4d 34 } //1 = Len(Join(Array("GvqL5K1EfGqUKZKeq4jvlCpnOM4
		$a_01_10 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 22 42 67 63 4a 4e 51 58 65 7a 34 36 47 6a 74 47 30 59 4f 39 58 4b 54 6f 44 35 6a 59 } //1 = Len(Join(Array("BgcJNQXez46GjtG0YO9XKToD5jY
		$a_01_11 = {3d 20 56 4d 56 78 74 5f 61 6c 6a 2e 7a 55 75 62 5f 66 75 5a 66 5f 59 77 7a 5f 72 32 63 } //1 = VMVxt_alj.zUub_fuZf_Ywz_r2c
		$a_01_12 = {3d 20 73 34 75 6c 69 49 4e 6c 6a 54 30 63 34 2e 68 54 5a 38 61 4d 42 45 63 } //1 = s4uliINljT0c4.hTZ8aMBEc
		$a_01_13 = {3d 20 79 49 32 50 4a 5f 4e 45 62 56 5f 71 67 55 56 5f 77 57 42 6f 2e 74 6b 6a 36 71 76 74 } //1 = yI2PJ_NEbV_qgUV_wWBo.tkj6qvt
		$a_01_14 = {3d 20 43 31 76 6e 35 36 66 35 2e 4a 36 69 73 4e 5f 6d 75 30 6c 5f 45 33 51 5f 78 57 34 } //1 = C1vn56f5.J6isN_mu0l_E3Q_xW4
		$a_01_15 = {3d 20 59 6c 59 38 50 51 66 45 5f 53 64 34 4b 41 41 5f 6c 71 79 59 54 37 5f 32 56 34 69 45 72 49 2e 5a 36 72 77 36 30 56 5f 67 72 45 65 48 50 68 } //1 = YlY8PQfE_Sd4KAA_lqyYT7_2V4iErI.Z6rw60V_grEeHPh
		$a_01_16 = {3d 20 5a 42 65 73 73 47 53 6e 5f 64 37 61 38 50 6b 5f 57 76 6a 55 39 6b 2e 6f 74 57 7a 6c 67 74 6b 5f 4b 73 6e 32 7a 6f } //1 = ZBessGSn_d7a8Pk_WvjU9k.otWzlgtk_Ksn2zo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1) >=7
 
}