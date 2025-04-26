
rule TrojanDownloader_O97M_IcedID_RVH_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.RVH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4f 62 6a 65 63 74 28 57 43 52 5f 41 77 28 22 57 41 35 63 47 79 34 64 22 29 29 2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 57 43 52 5f 41 77 28 22 74 63 61 7a 42 38 4c 5f 37 4a 22 29 29 2e 52 65 6d 6f 76 65 } //5 GetObject(WCR_Aw("WA5cGy4d")).Environment(WCR_Aw("tcazB8L_7J")).Remove
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 28 68 6f 43 48 72 47 42 5a 48 28 22 67 77 4e 4c 57 31 42 61 79 34 22 29 29 2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 68 6f 43 48 72 47 42 5a 48 28 22 53 63 6d 6f 7a 51 58 67 6f 6f 34 6c 79 22 29 29 2e 52 65 6d 6f 76 65 } //5 GetObject(hoCHrGBZH("gwNLW1Bay4")).Environment(hoCHrGBZH("ScmozQXgoo4ly")).Remove
		$a_01_2 = {47 65 74 4f 62 6a 65 63 74 28 70 56 4c 76 52 69 28 22 67 7a 56 52 65 46 57 5a 65 77 66 33 62 22 29 29 2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 70 56 4c 76 52 69 28 22 63 6d 4f 39 48 62 7a 39 63 6b 22 29 29 2e 52 65 6d 6f 76 65 } //5 GetObject(pVLvRi("gzVReFWZewf3b")).Environment(pVLvRi("cmO9Hbz9ck")).Remove
		$a_03_3 = {73 68 65 6c 6c 43 6f 64 65 2c 20 [0-27] 2c 20 36 34 2c 20 56 61 72 50 74 72 28 [0-27] 29 0d 0a 47 65 74 4f 62 6a 65 63 74 } //1
		$a_01_4 = {53 74 72 52 65 76 65 72 73 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 75 73 74 6f 6d 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 73 74 72 49 6e 70 75 74 29 29 } //1 StrReverse(ActiveDocument.CustomDocumentProperties(strInput))
		$a_01_5 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Sub Document_Open()
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}