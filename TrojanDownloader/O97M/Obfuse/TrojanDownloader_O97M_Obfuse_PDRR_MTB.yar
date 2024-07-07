
rule TrojanDownloader_O97M_Obfuse_PDRR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PDRR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4f 62 6a 65 63 74 28 54 38 71 63 65 62 30 58 28 22 79 4e 67 34 70 56 33 76 6d 51 5a 22 29 29 2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 54 38 71 63 65 62 30 58 28 22 4e 6c 42 56 55 62 61 51 22 29 29 2e 52 65 6d 6f 76 65 20 28 54 38 71 63 65 62 30 58 28 22 6c 56 4f 66 36 6e 75 4a 49 6e 22 29 29 } //1 GetObject(T8qceb0X("yNg4pV3vmQZ")).Environment(T8qceb0X("NlBVUbaQ")).Remove (T8qceb0X("lVOf6nuJIn"))
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 28 49 48 5a 6d 5f 33 4c 59 44 4a 47 45 28 22 4f 76 73 76 75 6a 78 36 6d 58 53 45 22 29 29 2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 49 48 5a 6d 5f 33 4c 59 44 4a 47 45 28 22 47 68 55 56 61 44 65 55 22 29 29 2e 52 65 6d 6f 76 65 20 28 49 48 5a 6d 5f 33 4c 59 44 4a 47 45 28 22 47 35 33 73 6d 4b 50 62 4e 22 29 29 } //1 GetObject(IHZm_3LYDJGE("Ovsvujx6mXSE")).Environment(IHZm_3LYDJGE("GhUVaDeU")).Remove (IHZm_3LYDJGE("G53smKPbN"))
		$a_01_2 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 75 73 74 6f 6d 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 73 74 72 49 6e 70 75 74 29 29 } //1 = StrReverse(ActiveDocument.CustomDocumentProperties(strInput))
		$a_01_3 = {3d 20 54 69 6d 65 72 28 29 20 2b 20 28 46 69 6e 69 73 68 29 } //1 = Timer() + (Finish)
		$a_03_4 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 90 02 0f 28 22 90 02 20 22 29 29 2e 56 61 6c 75 65 29 90 00 } //1
		$a_03_5 = {73 68 65 6c 6c 43 6f 64 65 2c 20 90 02 40 2c 20 36 34 2c 20 56 61 72 50 74 72 28 90 02 40 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}