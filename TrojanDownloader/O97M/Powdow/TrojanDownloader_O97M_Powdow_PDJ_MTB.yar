
rule TrojanDownloader_O97M_Powdow_PDJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 70 73 3a 2f 2f 69 6d 67 2e 32 30 6d 6e 2e 66 72 2f 72 35 53 76 78 71 53 5a 53 72 57 53 34 57 35 38 37 5f 65 4a 78 77 2f 36 34 30 78 34 31 30 5f 66 6f 6e 64 2d 65 63 72 61 6e 2d 64 65 66 61 75 74 2d 77 69 6e 64 6f 77 73 2d 78 70 2e 6a 70 67 } //1 powershell Start-BitsTransfer -Source https://img.20mn.fr/r5SvxqSZSrWS4W587_eJxw/640x410_fond-ecran-defaut-windows-xp.jpg
		$a_01_1 = {2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 47 69 73 65 6c 61 5c 44 6f 63 75 6d 65 6e 74 73 5c 69 6d 61 67 65 2e 6a 70 67 } //1 -Destination C:\Users\Gisela\Documents\image.jpg
		$a_01_2 = {73 74 72 4f 75 74 70 75 74 20 3d 20 52 75 6e 43 6f 6d 6d 61 6e 64 28 73 74 72 43 6f 6d 6d 61 6e 64 } //1 strOutput = RunCommand(strCommand
		$a_01_3 = {53 65 74 20 6f 62 6a 4e 6f 64 65 20 3d 20 6f 62 6a 58 4d 4c 2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 36 34 22 29 } //1 Set objNode = objXML.createElement("b64")
		$a_01_4 = {52 75 6e 43 6f 6d 6d 61 6e 64 20 3d 20 22 45 52 52 4f 52 22 } //1 RunCommand = "ERROR"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}