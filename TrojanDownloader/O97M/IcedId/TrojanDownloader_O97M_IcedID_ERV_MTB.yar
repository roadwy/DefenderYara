
rule TrojanDownloader_O97M_IcedID_ERV_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.ERV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 53 75 62 20 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 28 29 } //1 Public Sub button1_Click()
		$a_03_1 = {2e 65 78 65 63 20 28 73 72 28 [0-25] 29 29 90 0c 02 00 45 6e 64 20 57 69 74 68 90 0c 02 00 45 6e 64 20 53 75 62 } //1
		$a_01_2 = {3c 68 74 6d 6c 3e 3c 62 6f 64 79 3e 3c 64 69 76 20 69 64 3d 27 63 6f 6e 74 65 6e 74 31 27 3e 66 54 74 6c } //1 <html><body><div id='content1'>fTtl
		$a_03_3 = {66 72 6d 2e 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 90 0c 02 00 45 6e 64 20 53 75 62 } //1
		$a_01_4 = {3d 20 53 70 6c 69 74 28 73 72 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 74 69 74 6c 65 22 29 29 2c 20 22 20 22 29 } //1 = Split(sr(ActiveDocument.BuiltInDocumentProperties("title")), " ")
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}