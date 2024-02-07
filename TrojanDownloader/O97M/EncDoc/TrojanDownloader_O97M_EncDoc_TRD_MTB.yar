
rule TrojanDownloader_O97M_EncDoc_TRD_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.TRD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {23 49 66 20 57 69 6e 36 34 20 54 68 65 6e } //01 00  #If Win64 Then
		$a_01_1 = {41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 42 79 56 61 6c 20 70 43 61 6c 6c 65 72 20 41 73 20 4c 6f 6e 67 2c 20 5f } //01 00  Alias "URLDownloadToFileA" (ByVal pCaller As Long, _
		$a_01_2 = {42 79 56 61 6c 20 73 7a 55 52 4c 20 41 73 20 53 74 72 69 6e 67 2c 20 42 79 56 61 6c 20 73 7a 46 69 6c 65 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 2c 20 5f } //01 00  ByVal szURL As String, ByVal szFileName As String, _
		$a_01_3 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 56 69 73 62 6f 72 6e 28 29 } //01 00  Public Function Visborn()
		$a_01_4 = {73 69 6f 70 72 75 74 20 3d 20 22 68 74 22 20 26 20 22 74 70 3a 2f 2f 22 20 26 20 53 68 65 65 74 73 28 22 44 6f 63 73 32 22 29 2e 52 61 6e 67 65 28 22 42 35 30 22 29 } //01 00  sioprut = "ht" & "tp://" & Sheets("Docs2").Range("B50")
		$a_01_5 = {65 69 76 6d 66 73 63 20 3d 20 53 68 65 65 74 73 28 22 44 6f 63 73 32 22 29 2e 52 61 6e 67 65 28 22 53 35 22 29 } //01 00  eivmfsc = Sheets("Docs2").Range("S5")
		$a_03_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 73 69 6f 70 72 75 74 2c 20 65 69 76 6d 66 73 63 2c 20 30 2c 20 30 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}