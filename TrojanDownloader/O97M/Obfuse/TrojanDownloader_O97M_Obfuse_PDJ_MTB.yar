
rule TrojanDownloader_O97M_Obfuse_PDJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PDJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 20 73 61 65 28 35 29 20 26 20 73 61 65 28 36 29 20 26 20 73 61 65 28 37 29 20 26 20 73 61 65 28 38 29 20 26 20 73 61 65 28 39 29 20 26 20 73 61 65 28 31 30 29 20 26 20 73 61 65 28 31 31 29 20 26 } //01 00  & sae(5) & sae(6) & sae(7) & sae(8) & sae(9) & sae(10) & sae(11) &
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 4d 79 44 6f 63 75 6d 65 6e 74 73 22 29 20 26 20 22 5c 68 68 68 2e 7a 69 70 22 } //01 00  = CreateObject("WScript.Shell").SpecialFolders("MyDocuments") & "\hhh.zip"
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 4d 79 44 6f 63 75 6d 65 6e 74 73 22 29 20 26 20 22 5c 74 74 74 2e 7a 69 70 22 } //01 00  = CreateObject("WScript.Shell").SpecialFolders("MyDocuments") & "\ttt.zip"
		$a_01_3 = {3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 73 74 72 55 52 4c 2c 20 73 74 72 50 61 74 68 2c 20 30 2c 20 30 29 } //01 00  = URLDownloadToFile(0, strURL, strPath, 0, 0)
		$a_01_4 = {53 68 65 6c 6c 20 28 22 43 3a 5c 55 73 65 72 73 5c 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 55 73 65 72 4e 61 6d 65 22 29 20 26 20 22 5c 44 6f 63 75 6d 65 6e 74 73 22 20 26 20 22 78 6c 2e 70 6e 67 22 29 } //01 00  Shell ("C:\Users\" & Environ("UserName") & "\Documents" & "xl.png")
		$a_03_5 = {3d 20 70 61 74 68 6e 61 6d 65 20 26 20 22 5c 22 20 26 20 22 90 01 03 2e 7a 69 70 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}