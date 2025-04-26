
rule TrojanDownloader_O97M_Donoff_K{
	meta:
		description = "TrojanDownloader:O97M/Donoff.K,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {4c 69 62 20 22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 [0-03] 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 28 42 79 56 61 6c } //1
		$a_03_1 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 [0-03] 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 42 79 56 61 6c } //1
		$a_01_2 = {45 6e 76 69 72 6f 6e 24 28 22 74 6d 70 22 29 20 26 20 } //1 Environ$("tmp") & 
		$a_01_3 = {46 6f 72 20 78 20 3d 20 79 20 54 6f 20 31 20 53 74 65 70 20 2d 31 } //1 For x = y To 1 Step -1
		$a_01_4 = {28 22 66 79 66 2f } //1 ("fyf/
		$a_01_5 = {71 75 75 69 22 29 } //1 quui")
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Donoff_K_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.K,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 20 22 6d 73 68 74 61 20 6a 61 76 61 73 63 72 69 70 74 3a 22 22 5c 2e 2e 5c 6d 73 68 74 6d 6c 2c 52 75 6e 48 54 4d 4c 41 70 70 6c 69 63 61 74 69 6f 6e 20 22 22 3b 47 65 74 4f 62 6a 65 63 74 28 22 22 73 63 72 69 70 74 3a 68 74 74 70 3a 2f 22 20 2b 20 52 65 70 6c 61 63 65 28 61 62 61 64 6f 6e 64 65 6e 64 2c } //1 Shell "mshta javascript:""\..\mshtml,RunHTMLApplication "";GetObject(""script:http:/" + Replace(abadondend,
		$a_00_1 = {53 68 65 6c 6c 20 22 6d 73 68 74 61 20 6a 61 76 61 73 63 72 69 70 74 3a 22 22 5c 2e 2e 5c 6d 73 68 74 6d 6c 2c 52 75 6e 48 54 4d 4c 41 70 70 6c 69 63 61 74 69 6f 6e 20 22 22 3b 47 65 74 4f 62 6a 65 63 74 28 22 22 73 63 72 69 70 74 3a 68 74 74 70 3a } //1 Shell "mshta javascript:""\..\mshtml,RunHTMLApplication "";GetObject(""script:http:
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}