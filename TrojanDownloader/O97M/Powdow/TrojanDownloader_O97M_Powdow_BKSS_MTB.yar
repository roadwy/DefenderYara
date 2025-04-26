
rule TrojanDownloader_O97M_Powdow_BKSS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BKSS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 73 66 73 73 61 66 20 3d 20 22 73 64 66 73 61 66 22 } //1 dsfssaf = "sdfsaf"
		$a_01_1 = {64 73 66 64 61 73 20 3d 20 63 78 7a 76 78 7a 73 66 } //1 dsfdas = cxzvxzsf
		$a_01_2 = {3d 20 43 68 72 28 6f 70 68 6a 69 20 2d 20 31 33 30 29 } //1 = Chr(ophji - 130)
		$a_01_3 = {27 68 6a 67 6a 67 20 66 66 68 67 35 36 34 35 6e 20 2f 2a 2f } //1 'hjgjg ffhg5645n /*/
		$a_03_4 = {2e 52 75 6e 28 [0-32] 2c 20 [0-32] 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}