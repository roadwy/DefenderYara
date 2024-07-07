
rule TrojanDownloader_O97M_IcedID_SIS_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.SIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 75 73 74 6f 6d 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 73 74 72 49 6e 70 75 74 29 29 } //1 = StrReverse(ActiveDocument.CustomDocumentProperties(strInput))
		$a_03_1 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 90 02 1f 28 22 90 02 1f 22 29 29 2e 56 61 6c 75 65 29 90 00 } //1
		$a_01_2 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Sub Document_Open()
		$a_03_3 = {73 68 65 6c 6c 43 6f 64 65 2c 20 90 02 1e 2c 20 36 34 2c 20 56 61 72 50 74 72 28 90 02 1e 29 0d 0a 47 65 74 4f 62 6a 65 63 74 90 00 } //1
		$a_01_4 = {28 30 2c 20 73 68 65 6c 6c 43 6f 64 65 2c 20 31 2c 20 73 68 65 6c 6c 43 6f 64 65 29 } //1 (0, shellCode, 1, shellCode)
		$a_01_5 = {49 6e 74 28 52 6e 64 28 32 33 29 29 20 3e 20 32 20 54 68 65 6e } //1 Int(Rnd(23)) > 2 Then
		$a_01_6 = {3d 20 54 69 6d 65 72 28 29 20 2b 20 28 46 69 6e 69 73 68 29 } //1 = Timer() + (Finish)
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}