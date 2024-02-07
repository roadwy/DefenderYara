
rule TrojanDropper_O97M_GraceWire_DV_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 4f 66 62 6c 20 3d 20 6f 66 62 6c 20 2b 20 50 61 67 65 31 31 2e 52 61 6e 67 65 28 22 42 31 31 35 22 29 2e 56 61 6c 75 65 } //01 00  sOfbl = ofbl + Page11.Range("B115").Value
		$a_01_1 = {50 75 62 6c 69 63 52 65 73 75 6d 45 72 61 73 65 42 79 41 72 72 61 79 4c 69 73 74 20 6f 66 62 6c 20 2b 20 22 2a 22 2c 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 2b 20 22 5c 73 74 72 5f 6a 6f 69 6e 2a 22 2c 20 73 4f 66 62 6c 2c 20 63 74 61 63 6b 50 69 70 2c 20 64 65 72 73 68 6c 65 70 20 2b 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 54 61 67 } //01 00  PublicResumEraseByArrayList ofbl + "*", Form0.TextBox3.Tag + "\str_join*", sOfbl, ctackPip, dershlep + UserForm1.Label1.Tag
		$a_01_2 = {50 75 62 6c 69 63 52 65 73 75 6d 45 72 61 73 65 42 79 41 72 72 61 79 4c 69 73 74 20 6f 66 62 6c 20 2b 20 22 2a 22 2c 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 2b 20 22 5c 73 74 72 5f 6a 6f 69 6e 2a 22 2c 20 73 4f 66 62 6c 2c 20 63 74 61 63 6b 50 69 70 2c 20 64 65 72 73 68 6c 65 70 20 26 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 54 61 67 } //01 00  PublicResumEraseByArrayList ofbl + "*", Form0.TextBox3.Tag + "\str_join*", sOfbl, ctackPip, dershlep & UserForm1.Label1.Tag
		$a_01_3 = {63 74 61 63 6b 50 69 70 20 3d 20 6c 69 71 75 69 64 4f 6e 65 20 26 20 50 61 67 65 31 31 2e 52 61 6e 67 65 28 22 42 31 31 35 22 29 2e 56 61 6c 75 65 } //01 00  ctackPip = liquidOne & Page11.Range("B115").Value
		$a_01_4 = {53 65 74 20 45 78 63 65 6c 43 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 31 29 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 68 65 65 74 73 28 31 29 2e 41 70 70 6c 69 63 61 74 69 6f 6e } //00 00  Set ExcelC = ThisWorkbook.Sheets(1).Application.Sheets(1).Application
	condition:
		any of ($a_*)
 
}