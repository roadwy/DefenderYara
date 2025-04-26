
rule TrojanDownloader_O97M_Obfuse_DV{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DV,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 47 65 74 28 22 57 69 22 20 2b 20 22 6e 22 20 2b 20 22 33 32 5f 22 20 26 20 22 50 72 22 20 2b 20 22 6f 63 65 22 20 2b 20 22 73 73 22 20 26 20 22 53 74 22 20 2b 20 22 61 72 74 22 20 2b 20 22 75 70 22 29 } //1 = objWMIService.Get("Wi" + "n" + "32_" & "Pr" + "oce" + "ss" & "St" + "art" + "up")
		$a_01_1 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 48 49 44 44 45 4e 5f 57 49 4e 44 4f 57 } //1 .ShowWindow = HIDDEN_WINDOW
		$a_03_2 = {2e 43 72 65 61 74 65 20 50 76 53 28 22 [0-10] 22 29 20 26 20 [0-10] 2c 20 4e 75 6c 6c 2c 20 6f 62 6a 43 6f 6e 66 69 67 2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}