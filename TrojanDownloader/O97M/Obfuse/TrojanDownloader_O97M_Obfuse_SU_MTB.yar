
rule TrojanDownloader_O97M_Obfuse_SU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 61 67 65 73 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 Set ages = CreateObject("Shell.Application")
		$a_01_1 = {61 67 65 73 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 28 6b 6f 6c 61 29 } //1 ages.ShellExecute (kola)
		$a_01_2 = {6e 61 6d 65 20 3d 20 22 5c 5c 22 20 26 20 6e 61 6d 65 20 26 20 22 2e 6a 73 65 } //1 name = "\\" & name & ".jse
		$a_01_3 = {3d 20 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 } //1 = Environ("APPDATA")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_SU_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 6f 62 6a 4e 65 74 77 6f 72 6b 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 4e 65 74 77 6f 72 6b 22 29 } //1 Set objNetwork = CreateObject("WScript.Network")
		$a_01_1 = {3d 20 22 64 6f 20 73 68 65 6c 6c 20 73 63 72 69 70 74 20 22 20 26 20 43 68 72 24 28 33 34 29 20 26 20 22 6f 70 65 6e 20 2d 61 20 53 61 66 61 72 69 20 22 20 26 20 55 52 4c 20 26 20 43 68 72 24 28 33 34 29 } //1 = "do shell script " & Chr$(34) & "open -a Safari " & URL & Chr$(34)
		$a_01_2 = {3d 20 53 68 65 6c 6c 45 78 65 63 75 74 65 28 30 2c 20 22 4f 70 65 6e 22 2c 20 55 52 4c 29 } //1 = ShellExecute(0, "Open", URL)
		$a_01_3 = {3d 20 22 64 6f 20 73 68 65 6c 6c 20 73 63 72 69 70 74 20 22 20 26 20 43 68 72 24 28 33 34 29 20 26 20 22 2f 75 73 72 2f 62 69 6e 2f 63 75 72 6c 20 2d 2d 75 72 6c 20 22 20 26 20 55 52 4c 20 26 20 43 68 72 24 28 33 34 29 } //1 = "do shell script " & Chr$(34) & "/usr/bin/curl --url " & URL & Chr$(34)
		$a_03_4 = {3d 20 53 68 65 6c 6c 45 78 65 63 75 74 65 28 30 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 22 6e 65 74 22 2c 20 22 75 73 65 [0-0a] 22 20 26 20 55 52 4c 2c 20 22 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 22 2c 20 76 62 48 69 64 65 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}