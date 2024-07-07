
rule TrojanDownloader_O97M_Emotet_RVAA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RVAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 57 78 49 48 68 76 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 73 62 51 72 4b 57 65 2c 20 74 67 63 41 6d 63 2c 20 31 2c 20 75 41 73 42 29 } //1 HWxIHhv = CallByName(sbQrKWe, tgcAmc, 1, uAsB)
		$a_01_1 = {4d 69 64 28 43 69 61 2c 20 6a 58 45 46 28 71 79 29 2c 20 31 29 } //1 Mid(Cia, jXEF(qy), 1)
		$a_01_2 = {43 61 6c 6c 42 79 4e 61 6d 65 20 64 6c 6c 42 52 75 2c 20 6d 44 43 45 72 2c 20 31 2c 20 79 47 67 66 4f 2e 49 74 65 6d 73 2c 20 34 } //1 CallByName dllBRu, mDCEr, 1, yGgfO.Items, 4
		$a_01_3 = {41 75 74 6f 4f 70 65 6e 28 29 } //1 AutoOpen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}