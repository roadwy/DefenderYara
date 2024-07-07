
rule TrojanDownloader_O97M_Emotet_SAF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SAF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {20 3d 20 22 5d 61 6e 77 5b 33 72 6f 5d 61 6e 77 5b 33 5d 61 6e 77 5b 33 63 65 5d 61 6e 77 5b 33 73 5d 61 6e 77 5b 33 73 5d 61 6e 77 5b 33 5d 61 6e 77 5b 33 } //1  = "]anw[3ro]anw[3]anw[3ce]anw[3s]anw[3s]anw[3]anw[3
		$a_01_1 = {20 3d 20 22 5d 61 6e 77 5b 33 3a 77 5d 61 6e 77 5b 33 5d 61 6e 77 5b 33 69 6e 5d 61 6e 77 5b 33 33 5d 61 6e 77 5b 33 32 5d 61 6e 77 5b 33 5f 5d 61 6e 77 5b 33 } //1  = "]anw[3:w]anw[3]anw[3in]anw[33]anw[32]anw[3_]anw[3
		$a_01_2 = {20 3d 20 22 77 5d 61 6e 77 5b 33 69 6e 5d 61 6e 77 5b 33 6d 5d 61 6e 77 5b 33 67 6d 5d 61 6e 77 5b 33 74 5d 61 6e 77 5b 33 5d 61 6e 77 5b 33 } //1  = "w]anw[3in]anw[3m]anw[3gm]anw[3t]anw[3]anw[3
		$a_03_3 = {20 3d 20 52 65 70 6c 61 63 65 28 90 02 20 2c 20 22 5d 61 6e 77 5b 33 22 2c 20 90 02 20 29 90 00 } //1
		$a_03_4 = {2e 43 72 65 61 74 65 20 90 02 20 28 90 02 20 29 2c 20 90 02 20 2c 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}