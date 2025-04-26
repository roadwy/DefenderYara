
rule TrojanDownloader_O97M_Donoff_J{
	meta:
		description = "TrojanDownloader:O97M/Donoff.J,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {42 79 70 61 53 53 20 2d 6e 6f 70 72 6f 66 69 6c 65 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 [0-1e] 2e 70 68 70 27 2c 27 25 54 45 4d 50 25 5c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_J_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.J,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 7a 69 6d 6f 67 6f 73 74 6f 2e 72 75 } //1 dzimogosto.ru
		$a_01_1 = {2f 6e 6b 65 72 6e 65 6c 2e 65 78 65 } //1 /nkernel.exe
		$a_01_2 = {47 65 74 54 65 6d 70 50 61 74 68 28 32 35 35 2c 20 73 42 75 66 66 65 72 29 } //1 GetTempPath(255, sBuffer)
		$a_01_3 = {53 68 65 6c 6c 20 4c 6f 63 61 6c 46 69 6c 65 2c 20 76 62 48 69 64 65 } //1 Shell LocalFile, vbHide
		$a_01_4 = {72 65 74 20 3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 48 54 54 50 66 69 6c 65 } //1 ret = URLDownloadToFile(0, HTTPfile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}