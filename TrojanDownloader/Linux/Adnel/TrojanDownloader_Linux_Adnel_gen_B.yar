
rule TrojanDownloader_Linux_Adnel_gen_B{
	meta:
		description = "TrojanDownloader:Linux/Adnel.gen!B,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f [0-40] 2e 65 78 65 22 } //1
		$a_02_1 = {57 48 45 52 45 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 22 20 26 20 22 [0-20] 2e 65 78 65 22 } //1
		$a_00_2 = {44 6f 77 6e 6c 6f 61 64 53 74 61 74 75 73 20 3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 55 52 4c 2c 20 57 48 45 52 45 2c 20 30 2c 20 30 29 } //1 DownloadStatus = URLDownloadToFile(0, URL, WHERE, 0, 0)
		$a_00_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 57 48 45 52 45 } //1 CreateObject("WScript.Shell").Run WHERE
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}