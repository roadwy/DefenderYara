
rule TrojanDownloader_O97M_Obfuse_RVR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_02_0 = {77 77 77 2e 64 69 61 6d 61 6e 74 65 73 76 69 61 67 65 6e 73 2e 63 6f 6d 2e 62 72 2f 52 75 6e 2e 6a 70 67 22 90 0a 33 00 55 52 4c 20 3d 20 22 68 74 74 70 73 3a 2f 2f } //1
		$a_00_1 = {53 6c 65 65 70 20 36 30 30 30 30 } //1 Sleep 60000
		$a_00_2 = {73 74 61 72 74 75 70 66 6f 6c 64 65 72 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 22 } //1 startupfolder = "C:\Users\"
		$a_00_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 4e 65 74 77 6f 72 6b 22 29 2e 55 73 65 72 4e 61 6d 65 } //1 CreateObject("WScript.Network").UserName
		$a_00_4 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 22 20 2b 20 22 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 70 70 2e 62 61 74 } //1 AppData\Roaming\" + "Microsoft\Windows\Start Menu\Programs\Startup\pp.bat
		$a_00_5 = {41 75 78 69 6c 69 61 72 31 20 3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 75 72 6c 31 2c 20 43 61 6d 69 6e 68 6f 4c 6f 63 61 6c 2c 20 30 2c 20 30 29 } //1 Auxiliar1 = URLDownloadToFile(0, url1, CaminhoLocal, 0, 0)
		$a_00_6 = {61 75 74 6f 5f 6f 70 65 6e 28 29 } //1 auto_open()
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}