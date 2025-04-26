
rule TrojanDownloader_O97M_Powdow_RVAD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVAD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 42 79 4e 61 6d 65 28 73 53 56 6e 6f 2c 20 52 69 6a 78 75 79 64 44 28 22 20 53 20 68 20 65 20 6c 20 6c 20 45 20 78 20 65 20 63 20 75 20 74 20 65 20 22 29 2c 20 56 62 4d 65 74 68 6f 64 2c 20 44 47 6a 47 } //1 CallByName(sSVno, RijxuydD(" S h e l l E x e c u t e "), VbMethod, DGjG
		$a_01_1 = {52 69 6a 78 75 79 64 44 28 22 53 20 68 20 65 20 6c 20 6c 20 2e 20 41 20 70 20 70 20 6c 20 69 20 63 20 61 20 74 20 69 20 6f 20 6e 22 29 } //1 RijxuydD("S h e l l . A p p l i c a t i o n")
		$a_01_2 = {44 47 6a 47 28 30 29 20 3d 20 22 70 22 20 2b 20 69 66 67 6b 64 66 67 } //1 DGjG(0) = "p" + ifgkdfg
		$a_01_3 = {67 35 20 3d 20 43 65 6c 6c 73 28 32 2c 20 37 29 0d 0a 67 36 20 3d 20 43 65 6c 6c 73 28 33 2c 20 37 29 } //1
		$a_01_4 = {63 68 61 72 20 3d 20 4d 69 64 28 77 6a 6b 77 65 72 2c 20 69 2c 20 31 29 } //1 char = Mid(wjkwer, i, 1)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}