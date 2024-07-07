
rule TrojanDownloader_O97M_Shrewtee_A{
	meta:
		description = "TrojanDownloader:O97M/Shrewtee.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_01_1 = {57 48 45 52 45 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 22 20 26 20 22 74 65 73 74 2e 65 78 65 } //1 WHERE = Environ("Temp") & "\" & "test.exe
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 53 74 61 74 75 73 20 3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 55 52 4c 2c 20 57 48 45 52 45 2c 20 30 2c 20 30 29 } //1 DownloadStatus = URLDownloadToFile(0, URL, WHERE, 0, 0)
		$a_01_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 57 48 45 52 45 } //1 CreateObject("WScript.Shell").Run WHERE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}