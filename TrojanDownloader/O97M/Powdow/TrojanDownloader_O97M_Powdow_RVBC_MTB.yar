
rule TrojanDownloader_O97M_Powdow_RVBC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6f 62 6a 2e 41 64 64 20 22 61 6b 73 6a 64 6c 61 6b 73 6a 64 71 6f 77 69 6a 64 65 6e 65 77 63 22 } //1 obj.Add "aksjdlaksjdqowijdenewc"
		$a_01_1 = {22 68 74 22 0d 0a 6f 62 6a 2e 41 64 64 20 22 74 70 73 22 } //1
		$a_01_2 = {4d 69 64 24 28 73 74 72 54 65 78 74 2c 20 31 2c 20 6c 6e 67 55 73 65 64 29 } //1 Mid$(strText, 1, lngUsed)
		$a_01_3 = {6f 6e 65 73 65 73 65 73 65 20 3d 20 6f 62 6a 2e 47 65 74 53 74 72 } //1 onesesese = obj.GetStr
		$a_01_4 = {43 61 6c 6c 20 41 4c 4b 53 4a 44 4b 4c 41 53 4a 44 4c 4b 41 4a 53 44 4c 4b 41 4a 53 44 4b 4c 4a 41 53 4c 4b 44 4a 4c 4b 41 53 4b 4c 41 53 4e 43 4d 4c 53 41 4e 43 4d 41 53 } //1 Call ALKSJDKLASJDLKAJSDLKAJSDKLJASLKDJLKASKLASNCMLSANCMAS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Powdow_RVBC_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 57 53 43 52 49 50 54 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 50 69 63 74 75 72 65 73 5c 74 65 78 74 66 69 6c 65 2e 4a 53 22 0d 0a 43 61 6c 6c 20 53 68 65 6c 6c 28 61 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 } //1
		$a_01_1 = {57 6f 72 6b 73 68 65 65 74 73 28 22 53 68 65 65 74 32 22 29 2e 52 61 6e 67 65 28 22 53 4f 58 31 30 38 22 29 0d 0a 50 72 69 6e 74 20 23 54 65 78 74 46 69 6c 65 2c 20 79 6f 75 74 75 62 65 } //1
		$a_01_2 = {4f 70 65 6e 20 6d 79 46 69 6c 65 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 54 65 78 74 46 69 6c 65 } //1 Open myFile For Output As TextFile
		$a_01_3 = {57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } //1 Workbook_Open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}