
rule TrojanDownloader_O97M_IcedID_FAAC_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.FAAC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {47 65 74 4f 62 6a 65 63 74 28 64 65 6c 65 74 65 54 65 6d 70 54 69 74 6c 65 20 26 20 22 22 29 2e 4e 61 76 69 67 61 74 65 20 74 69 74 6c 65 90 0c 02 00 45 6e 64 20 53 75 62 } //1
		$a_01_1 = {74 69 74 6c 65 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 74 69 74 6c 65 22 29 } //1 title = ActiveDocument.BuiltInDocumentProperties("title")
		$a_03_2 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 73 75 62 6a 65 63 74 22 29 20 26 20 22 22 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_01_3 = {4f 70 65 6e 20 74 69 74 6c 65 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 } //1 Open title For Output As #1
		$a_03_4 = {50 72 69 6e 74 20 23 31 2c 20 [0-20] 2e 52 61 6e 67 65 2e 54 65 78 74 90 0c 02 00 43 6c 6f 73 65 20 23 31 } //1
		$a_01_5 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 42 61 73 65 20 3d 20 22 31 4e 6f 72 6d 61 6c 2e 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 } //1 Attribute VB_Base = "1Normal.ThisDocument"
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}