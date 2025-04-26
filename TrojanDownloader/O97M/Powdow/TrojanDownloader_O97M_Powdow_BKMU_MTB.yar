
rule TrojanDownloader_O97M_Powdow_BKMU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BKMU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 76 75 6e 20 3d 20 6a 76 75 6e 20 26 } //1 jvun = jvun &
		$a_01_1 = {2e 52 75 6e 28 6e 75 6a 76 66 74 69 64 78 2c 20 62 6c 6a 64 61 77 75 75 76 6d 79 6f 7a 6e 73 62 6b 71 75 6e 77 77 77 79 70 6c 64 71 78 62 6f 62 64 64 76 6c 62 29 } //1 .Run(nujvftidx, bljdawuuvmyoznsbkqunwwwypldqxbobddvlb)
		$a_01_2 = {63 6e 6c 2e 6a 76 78 } //1 cnl.jvx
		$a_01_3 = {6a 68 74 66 68 70 75 20 28 69 62 65 71 70 6d 6e 6e 7a 78 71 67 6b 73 75 6b 74 77 69 29 } //1 jhtfhpu (ibeqpmnnzxqgksuktwi)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_BKMU_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BKMU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 76 70 20 3d 20 6f 76 70 20 26 } //1 ovp = ovp &
		$a_01_1 = {7a 73 6e 6c 78 67 68 6f 7a 79 6e 61 6a 62 74 70 75 74 77 76 71 74 67 72 62 72 6c 61 72 6a 62 61 75 61 20 28 76 66 6a 66 73 66 76 79 6a 61 6a 69 79 75 62 74 66 29 } //1 zsnlxghozynajbtputwvqtgrbrlarjbaua (vfjfsfvyjajiyubtf)
		$a_01_2 = {73 77 6c 2e 7a 7a 61 78 } //1 swl.zzax
		$a_01_3 = {2e 52 75 6e 28 75 75 73 7a 73 72 78 6b 6e 6b 7a 6a 73 63 65 73 74 75 2c 20 6f 73 74 74 79 71 6b 6d 67 62 6b 67 68 68 6c 71 77 79 67 74 79 6e 63 79 65 78 75 66 74 74 76 78 29 } //1 .Run(uuszsrxknkzjscestu, osttyqkmgbkghhlqwygtyncyexufttvx)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}