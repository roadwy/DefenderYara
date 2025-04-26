
rule TrojanDownloader_O97M_Obfuse_FR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_00_0 = {41 75 74 6f 4f 70 65 6e 28 29 } //1 AutoOpen()
		$a_00_1 = {41 63 74 69 76 65 57 69 6e 64 6f 77 2e 44 6f 63 75 6d 65 6e 74 4d 61 70 } //1 ActiveWindow.DocumentMap
		$a_00_2 = {41 63 74 69 76 65 57 69 6e 64 6f 77 2e 44 69 73 70 6c 61 79 56 65 72 74 69 63 61 6c } //1 ActiveWindow.DisplayVertical
		$a_00_3 = {45 6e 76 69 72 6f 6e 28 22 74 6d 70 22 29 20 26 20 22 5c 69 6e 64 65 78 2e 6a 70 67 22 } //1 Environ("tmp") & "\index.jpg"
		$a_00_4 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 63 74 69 76 65 54 68 65 6d 65 44 69 73 70 6c 61 79 4e 61 6d 65 } //1 ActiveDocument.ActiveThemeDisplayName
		$a_00_5 = {43 61 6c 6c 20 66 34 39 39 64 30 66 38 2e 65 78 65 } //1 Call f499d0f8.exe
		$a_00_6 = {43 61 6c 6c 20 61 38 61 30 65 35 38 35 2e 65 78 65 } //1 Call a8a0e585.exe
		$a_00_7 = {2e 4f 70 65 6e 28 22 47 45 54 22 2c 20 64 33 33 39 35 65 34 62 2c 20 46 61 6c 73 65 29 } //1 .Open("GET", d3395e4b, False)
		$a_00_8 = {2e 4f 70 65 6e 28 22 47 45 54 22 2c 20 66 65 33 32 61 35 63 61 2c 20 46 61 6c 73 65 29 } //1 .Open("GET", fe32a5ca, False)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=7
 
}