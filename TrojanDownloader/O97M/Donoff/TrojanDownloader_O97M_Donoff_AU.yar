
rule TrojanDownloader_O97M_Donoff_AU{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AU,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 ?? 22 20 28 42 79 56 61 6c } //1
		$a_03_1 = {4c 69 62 20 22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 53 68 65 6c 6c 45 78 65 63 75 74 65 ?? 22 20 28 42 79 56 61 6c } //1
		$a_01_2 = {70 61 74 63 68 5f 74 6f 5f 6d 79 5f 66 69 6c 65 20 3d 20 22 68 74 74 70 3a 22 20 26 20 61 20 26 20 61 20 26 } //1 patch_to_my_file = "http:" & a & a &
		$a_01_3 = {74 6d 70 5f 66 6f 6c 64 65 72 20 3d 20 61 20 26 20 22 5c 22 20 26 20 4d 69 64 28 55 52 4c 2c 20 49 6e 53 74 72 52 65 76 28 55 52 4c 2c 20 22 2f 22 29 20 2b 20 31 2c 20 4c 65 6e 28 55 52 4c 29 29 } //1 tmp_folder = a & "\" & Mid(URL, InStrRev(URL, "/") + 1, Len(URL))
		$a_01_4 = {2e 6f 62 66 5f 72 75 6e 6e 65 72 20 66 69 6c 65 5f 74 6f 5f 73 61 76 65 2c 20 63 6f 6e 74 65 6e 74 2c 20 72 65 6d 6f 74 65 75 72 6c } //1 .obf_runner file_to_save, content, remoteurl
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}