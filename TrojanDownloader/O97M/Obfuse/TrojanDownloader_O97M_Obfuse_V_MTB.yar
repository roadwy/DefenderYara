
rule TrojanDownloader_O97M_Obfuse_V_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.V!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 45 6e 76 69 72 6f 6e 24 28 22 48 4f 4d 45 50 41 54 48 22 29 20 26 20 22 5c 5c 22 20 26 20 22 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 70 65 70 73 69 2e 62 61 74 22 2c } //1 .CreateTextFile(Environ$("HOMEPATH") & "\\" & "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\pepsi.bat",
		$a_03_1 = {2e 57 72 69 74 65 20 [0-1e] 26 20 22 22 20 26 20 [0-1e] 26 20 22 20 2d 66 20 2d 64 65 63 6f 64 65 20 22 22 43 3a 25 48 4f 4d 45 50 41 54 48 25 5c 64 57 69 66 69 22 } //1
		$a_01_2 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 45 6e 76 69 72 6f 6e 24 28 22 48 4f 4d 45 50 41 54 48 22 29 20 26 20 22 5c 5c 22 20 26 20 22 64 57 69 66 69 22 2c } //1 .CreateTextFile(Environ$("HOMEPATH") & "\\" & "dWifi",
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}