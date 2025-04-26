
rule TrojanDownloader_O97M_Powdow_ALV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.ALV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 6d 61 67 65 54 79 70 65 20 3d 20 22 70 6e 67 22 20 27 20 6f 72 20 6a 70 67 20 6f 72 20 62 6d 70 } //1 imageType = "png" ' or jpg or bmp
		$a_01_1 = {43 53 44 43 44 53 20 3d 20 22 64 63 64 76 20 68 67 66 6e 20 6d 6a 68 67 6d 6a 22 } //1 CSDCDS = "dcdv hgfn mjhgmj"
		$a_01_2 = {6d 61 67 65 4e 61 6d 65 20 3d 20 4c 65 66 74 28 70 70 74 4e 61 6d 65 2c 20 49 6e 53 74 72 28 70 70 74 4e 61 6d 65 2c 20 22 2e 22 29 29 20 26 20 69 6d 61 67 65 54 79 70 65 } //1 mageName = Left(pptName, InStr(pptName, ".")) & imageType
		$a_01_3 = {72 79 6b 67 20 3d 20 69 6f 79 75 6b 69 75 28 31 38 33 29 20 26 20 69 6f 79 75 6b 69 75 28 32 32 35 29 20 26 20 69 6f 79 75 6b 69 75 28 32 31 36 29 20 26 20 69 6f 79 75 6b 69 75 28 31 34 38 29 20 26 20 69 6f 79 75 6b 69 75 28 31 36 33 29 20 26 20 69 6f 79 75 6b 69 75 28 31 38 33 29 20 26 } //1 rykg = ioyukiu(183) & ioyukiu(225) & ioyukiu(216) & ioyukiu(148) & ioyukiu(163) & ioyukiu(183) &
		$a_01_4 = {3d 20 64 68 64 7a 78 71 65 76 73 72 70 7a 67 6b 71 7a 68 77 72 70 62 72 62 78 6d 77 65 76 76 66 6e 2e 52 75 6e 28 78 6e 74 6f 77 77 6e 78 6f 78 79 67 79 67 73 6c 74 6d 7a 65 69 77 68 71 2c 20 72 66 74 6a 73 29 } //1 = dhdzxqevsrpzgkqzhwrpbrbxmwevvfn.Run(xntowwnxoxygygsltmzeiwhq, rftjs)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}