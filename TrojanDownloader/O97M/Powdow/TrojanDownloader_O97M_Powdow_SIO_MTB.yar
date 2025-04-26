
rule TrojanDownloader_O97M_Powdow_SIO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SIO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 74 65 6d 70 50 61 74 68 20 26 20 22 5c 6b 72 6f 6e 6f 73 2e 62 61 74 22 2c 20 30 2c 20 46 61 6c 73 65 } //1 objShell.Run tempPath & "\kronos.bat", 0, False
		$a_01_1 = {64 6f 77 6e 6c 6f 61 64 55 52 4c 20 3d 20 22 68 74 74 70 73 3a 2f 2f 76 61 6c 61 6d 69 2e 68 75 22 } //1 downloadURL = "https://valami.hu"
		$a_01_2 = {6f 62 6a 46 69 6c 65 2e 57 72 69 74 65 4c 69 6e 65 20 22 63 75 72 6c 20 2d 6f 20 22 22 25 64 6f 77 6e 6c 6f 61 64 65 64 46 69 6c 65 25 22 22 20 2d 4c 20 22 22 25 64 6f 77 6e 6c 6f 61 64 55 52 4c 25 22 22 22 } //1 objFile.WriteLine "curl -o ""%downloadedFile%"" -L ""%downloadURL%"""
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}