
rule TrojanDownloader_O97M_Powdow_ALS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.ALS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {50 72 69 76 61 74 65 20 53 75 62 20 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 28 29 [0-06] 45 6e 64 20 53 75 62 } //1
		$a_01_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 4d 6f 64 75 6c 65 31 31 31 22 } //1 Attribute VB_Name = "Module111"
		$a_03_2 = {53 75 62 20 5f 90 0c 02 00 41 75 74 6f 5f 4f 70 65 6e 20 5f 90 0c 02 00 28 29 } //1
		$a_01_3 = {53 65 74 20 4f 75 74 6c 6f 6f 6b 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4f 75 74 6c 6f 6f 6b 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 Set Outlook = CreateObject("Outlook.Application")
		$a_01_4 = {53 65 74 20 4d 69 63 72 6f 73 6f 66 74 20 3d 20 4f 75 74 6c 6f 6f 6b 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 Set Microsoft = Outlook.CreateObject("Shell.Application")
		$a_03_5 = {4d 69 63 72 6f 73 6f 66 74 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 68 6f 6c 61 2e 67 6f 6c 61 2e 41 63 63 65 6c 65 72 61 74 6f 72 20 2b 20 68 6f 6c 61 2e 67 6f 6c 61 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 2c 20 68 6f 6c 61 2e 67 6f 6c 61 2e 43 61 70 74 69 6f 6e 90 0c 02 00 45 6e 64 20 5f 90 0c 02 00 53 75 62 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}