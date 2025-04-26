
rule TrojanDownloader_O97M_Powdow_BYK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BYK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 79 4b 46 5f 2e 72 4a 5f 70 5f 38 6c 69 6c 33 52 70 71 4f 76 76 5f 4f 5f 57 } //1 nyKF_.rJ_p_8lil3RpqOvv_O_W
		$a_01_1 = {64 5f 5f 5f 66 73 61 20 3d 20 43 68 72 28 73 5f 5f 64 20 2d 20 32 32 29 } //1 d___fsa = Chr(s__d - 22)
		$a_01_2 = {2e 52 75 6e 28 70 4d 54 76 5f 37 43 32 66 59 6a 4e 2c 20 74 5f 4f 57 4a 47 78 45 37 66 64 46 78 72 5f 74 5f 74 29 } //1 .Run(pMTv_7C2fYjN, t_OWJGxE7fdFxr_t_t)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_BYK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BYK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 4b 38 50 71 2e 45 59 4c 45 4c 70 63 74 77 33 64 51 58 64 54 41 5f 6e 5f 66 } //1 HK8Pq.EYLELpctw3dQXdTA_n_f
		$a_01_1 = {64 5f 5f 5f 66 73 61 20 3d 20 43 68 72 28 73 5f 5f 64 20 2d 20 32 32 29 } //1 d___fsa = Chr(s__d - 22)
		$a_01_2 = {2e 52 75 6e 28 4c 67 39 36 36 61 5f 38 44 56 2c 20 63 6b 46 5f 77 5f 68 61 6f 6b 31 42 32 5f 4a 4e 37 6f 4f 31 73 6c 4a 74 29 } //1 .Run(Lg966a_8DV, ckF_w_haok1B2_JN7oO1slJt)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_BYK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BYK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 68 35 5f 5f 36 38 35 2e 7a 54 59 4a 6c 54 33 5a 71 53 6a 61 62 56 56 46 56 48 48 61 } //1 th5__685.zTYJlT3ZqSjabVVFVHHa
		$a_01_1 = {64 5f 5f 5f 66 73 61 20 3d 20 43 68 72 28 73 5f 5f 64 20 2d 20 32 32 29 } //1 d___fsa = Chr(s__d - 22)
		$a_01_2 = {2e 52 75 6e 28 52 6f 6f 75 47 67 5f 54 53 5a 71 5f 70 79 64 76 65 4f 54 5a 2c 20 52 5f 5f 63 31 42 35 75 4d 34 63 29 } //1 .Run(RoouGg_TSZq_pydveOTZ, R__c1B5uM4c)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}