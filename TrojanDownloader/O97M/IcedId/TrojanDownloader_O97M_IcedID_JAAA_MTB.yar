
rule TrojanDownloader_O97M_IcedID_JAAA_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.JAAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
		$a_01_1 = {6c 69 62 4c 65 66 74 49 6e 64 65 78 } //1 libLeftIndex
		$a_01_2 = {6c 69 6e 6b 43 6f 6c 6c 65 63 74 69 6f 6e 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 } //1 linkCollection = ActiveDocument.Content
		$a_01_3 = {6c 69 6e 6b 43 6f 6c 6c 65 63 74 69 6f 6e 20 3d 20 4d 69 64 28 6c 69 6e 6b 43 6f 6c 6c 65 63 74 69 6f 6e 2c 20 32 2c 20 4c 65 6e 28 6c 69 6e 6b 43 6f 6c 6c 65 63 74 69 6f 6e 29 29 } //1 linkCollection = Mid(linkCollection, 2, Len(linkCollection))
		$a_01_4 = {57 69 74 68 20 74 61 62 6c 65 54 69 74 6c 65 2e 44 6f 63 75 6d 65 6e 74 73 2e 41 64 64 2e 56 42 50 72 6f 6a 65 63 74 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 28 22 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 29 2e 43 6f 64 65 4d 6f 64 75 6c 65 } //1 With tableTitle.Documents.Add.VBProject.VBComponents("ThisDocument").CodeModule
		$a_01_5 = {3d 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 22 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 56 65 72 73 69 6f 6e 20 26 20 22 5c 57 6f 72 64 5c 53 65 63 75 72 69 74 79 5c 41 63 63 65 73 73 56 42 4f 4d 22 } //1 = "HKEY_CURRENT_USER\Software\Microsoft\Office\" & Application.Version & "\Word\Security\AccessVBOM"
		$a_03_6 = {57 69 74 68 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 90 0c 02 00 2e 52 65 67 57 72 69 74 65 20 72 65 6d 6f 76 65 4e 65 78 74 2c 20 31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22 90 0c 02 00 45 6e 64 20 57 69 74 68 90 0c 02 00 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}