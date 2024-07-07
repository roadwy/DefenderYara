
rule TrojanDownloader_O97M_Powdow_QVST_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.QVST!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 32 20 3d 20 2e 54 65 78 74 42 6f 78 65 73 28 22 54 65 78 74 42 6f 78 20 31 22 29 2e 4e 61 6d 65 } //1 F2 = .TextBoxes("TextBox 1").Name
		$a_01_1 = {53 65 74 20 6e 74 70 61 6c 4c 4d 52 4e 20 3d 20 65 48 54 6b 6e 2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 42 5a 4e 64 20 2b 20 22 5c 51 41 49 54 42 2e 76 62 73 22 2c 20 38 2c 20 54 72 75 65 29 } //1 Set ntpalLMRN = eHTkn.OpenTextFile(BZNd + "\QAITB.vbs", 8, True)
		$a_01_2 = {6f 67 52 78 20 3d 20 6c 50 4e 6d 50 67 2e 4f 70 65 6e 28 66 35 66 67 30 65 20 2b 20 22 5c 51 41 49 54 42 2e 76 62 73 22 29 } //1 ogRx = lPNmPg.Open(f5fg0e + "\QAITB.vbs")
		$a_01_3 = {45 6e 64 54 69 63 6b 20 3d 20 47 65 74 54 69 63 6b 43 6f 75 6e 74 20 2b 20 28 46 69 6e 69 73 68 20 2a 20 31 30 30 30 29 } //1 EndTick = GetTickCount + (Finish * 1000)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}