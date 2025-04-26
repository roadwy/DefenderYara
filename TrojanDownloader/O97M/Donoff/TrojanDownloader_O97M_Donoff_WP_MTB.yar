
rule TrojanDownloader_O97M_Donoff_WP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.WP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 20 28 4e 61 4d 6d 59 70 5a 6d 4f 62 46 74 29 } //1 Shell (NaMmYpZmObFt)
		$a_00_1 = {51 6b 44 65 41 63 42 61 47 73 55 6a 20 3d 20 43 68 72 28 4c 6e 4e 72 46 62 52 63 43 6d 4e 63 29 } //1 QkDeAcBaGsUj = Chr(LnNrFbRcCmNc)
		$a_00_2 = {4e 61 4d 6d 59 70 5a 6d 4f 62 46 74 20 3d 20 51 6b 44 65 41 63 42 61 47 73 55 6a 20 2b 20 50 6d 4f 76 51 72 4b 6c 58 69 44 75 20 2b 20 47 69 52 78 57 6b 49 7a 5a 69 55 62 } //1 NaMmYpZmObFt = QkDeAcBaGsUj + PmOvQrKlXiDu + GiRxWkIzZiUb
		$a_00_3 = {43 61 4d 6f 4d 77 55 6e 41 65 58 69 20 3d 20 32 38 32 31 36 37 32 37 35 } //1 CaMoMwUnAeXi = 282167275
		$a_00_4 = {4c 6e 4e 72 46 62 52 63 43 6d 4e 63 20 3d 20 59 6f 41 6b 58 67 56 69 50 79 49 69 20 2d 20 43 61 4d 6f 4d 77 55 6e 41 65 58 69 } //1 LnNrFbRcCmNc = YoAkXgViPyIi - CaMoMwUnAeXi
		$a_00_5 = {42 63 43 68 58 6a 42 74 4f 68 5a 72 20 3d 20 32 38 32 31 36 37 33 39 32 } //1 BcChXjBtOhZr = 282167392
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}