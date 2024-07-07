
rule TrojanDownloader_O97M_Powdow_RVAC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVAC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 55 72 6c 20 3d 20 22 68 74 74 70 3a 2f 2f 77 77 77 2e 62 6f 6f 6b 69 71 2e 62 73 6e 6c 2e 63 6f 2e 69 6e 2f 64 61 74 61 5f 65 6e 74 72 79 2f 63 69 72 63 75 6c 61 72 73 2f 6d 6d 61 61 63 63 63 2e 65 78 65 22 } //1 FileUrl = "http://www.bookiq.bsnl.co.in/data_entry/circulars/mmaaccc.exe"
		$a_01_1 = {53 68 65 6c 6c 20 28 22 66 69 6c 65 31 2e 65 78 65 22 29 } //1 Shell ("file1.exe")
		$a_01_2 = {45 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 20 26 20 22 5c 4d 69 63 72 6f 73 6f 66 74 5c 54 65 6d 70 6c 61 74 65 73 5c 22 20 26 20 44 61 74 65 44 69 66 66 28 22 73 22 2c 20 23 31 2f 31 2f 31 39 37 30 23 2c 20 4e 6f 77 28 29 29 20 26 20 22 2e 64 6f 74 6d 22 } //1 Environ("appdata") & "\Microsoft\Templates\" & DateDiff("s", #1/1/1970#, Now()) & ".dotm"
		$a_01_3 = {6f 62 6a 53 74 72 65 61 6d 2e 53 61 76 65 54 6f 46 69 6c 65 20 22 66 69 6c 65 31 2e 65 78 65 22 2c 20 32 } //1 objStream.SaveToFile "file1.exe", 2
		$a_01_4 = {61 75 74 6f 6f 70 65 6e 28 29 0d 0a 20 20 20 20 63 75 72 66 69 6c 65 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 50 61 74 68 20 26 20 22 5c 22 20 26 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 4e 61 6d 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}