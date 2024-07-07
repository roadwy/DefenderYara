
rule TrojanDownloader_O97M_Powdow_BKSN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BKSN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 61 73 66 73 64 20 3d 20 7a 78 63 7a 78 } //1 dasfsd = zxczx
		$a_01_1 = {43 61 6c 6c 20 65 62 7a 78 70 2e 61 77 6f 69 63 65 65 63 6a 70 6a 78 74 69 63 79 66 66 6e 62 } //1 Call ebzxp.awoiceecjpjxticyffnb
		$a_01_2 = {64 73 66 64 73 61 20 3d 20 31 32 33 32 31 } //1 dsfdsa = 12321
		$a_01_3 = {6e 67 78 65 74 6a 62 20 3d 20 68 62 6a 73 64 28 } //1 ngxetjb = hbjsd(
		$a_03_4 = {2e 52 75 6e 28 90 02 32 2c 20 90 02 32 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}