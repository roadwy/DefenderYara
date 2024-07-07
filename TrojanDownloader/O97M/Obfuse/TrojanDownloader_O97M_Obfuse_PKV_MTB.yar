
rule TrojanDownloader_O97M_Obfuse_PKV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PKV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 61 64 6e 6f 63 2d 64 69 73 74 72 69 62 75 74 69 6f 6e 73 2e 63 6f 6d 2f 70 72 6f 6a 65 63 74 73 2f 65 6e 71 75 69 72 79 2e 7a 69 70 } //1 .adnoc-distributions.com/projects/enquiry.zip
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 55 73 65 72 4e 61 6d 65 22 29 20 26 20 22 5c 44 6f 63 75 6d 65 6e 74 73 } //1 C:\Users\" & Environ("UserName") & "\Documents
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 4d 79 44 6f 63 75 6d 65 6e 74 73 22 29 } //1 = CreateObject("WScript.Shell").SpecialFolders("MyDocuments")
		$a_01_3 = {3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 73 74 72 55 52 4c 2c 20 73 74 72 50 61 74 68 2c 20 30 2c 20 30 29 } //1 = URLDownloadToFile(0, strURL, strPath, 0, 0)
		$a_01_4 = {53 68 65 6c 6c 41 70 70 2e 4e 61 6d 65 73 70 61 63 65 28 75 6e 7a 69 70 54 6f 50 61 74 68 29 2e 43 6f 70 79 48 65 72 65 20 53 68 65 6c 6c 41 70 70 2e 4e 61 6d 65 73 70 61 63 65 28 7a 69 70 70 65 64 46 69 6c 65 46 75 6c 6c 4e 61 6d 65 29 2e 49 74 65 6d 73 } //1 ShellApp.Namespace(unzipToPath).CopyHere ShellApp.Namespace(zippedFileFullName).Items
		$a_01_5 = {54 68 65 6e 20 4d 73 67 42 6f 78 20 22 53 6f 6d 65 74 68 69 6e 67 20 77 65 6e 74 20 77 72 6f 6e 67 21 } //1 Then MsgBox "Something went wrong!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}