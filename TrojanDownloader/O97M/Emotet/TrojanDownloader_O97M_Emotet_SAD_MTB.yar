
rule TrojanDownloader_O97M_Emotet_SAD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SAD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {20 3d 20 22 5d 65 31 72 5b 53 72 6f 5d 65 31 72 5b 53 5d 65 31 72 5b 53 63 65 5d 65 31 72 5b 53 73 5d 65 31 72 5b 53 73 5d 65 31 72 5b 53 5d 65 31 72 5b 53 22 } //1  = "]e1r[Sro]e1r[S]e1r[Sce]e1r[Ss]e1r[Ss]e1r[S]e1r[S"
		$a_01_1 = {20 3d 20 22 5d 65 31 72 5b 53 3a 77 5d 65 31 72 5b 53 5d 65 31 72 5b 53 69 6e 5d 65 31 72 5b 53 33 5d 65 31 72 5b 53 32 5d 65 31 72 5b 53 5f 5d 65 31 72 5b 53 22 } //1  = "]e1r[S:w]e1r[S]e1r[Sin]e1r[S3]e1r[S2]e1r[S_]e1r[S"
		$a_01_2 = {20 3d 20 22 77 5d 65 31 72 5b 53 69 6e 5d 65 31 72 5b 53 6d 5d 65 31 72 5b 53 67 6d 5d 65 31 72 5b 53 74 5d 65 31 72 5b 53 5d 65 31 72 5b 53 22 } //1  = "w]e1r[Sin]e1r[Sm]e1r[Sgm]e1r[St]e1r[S]e1r[S"
		$a_03_3 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-20] 2c 20 22 5d 65 31 72 5b 53 22 2c 20 [0-20] 29 } //1
		$a_03_4 = {2e 43 72 65 61 74 65 20 [0-20] 28 [0-20] 29 2c 20 [0-20] 2c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}