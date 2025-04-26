
rule TrojanDownloader_O97M_Skebpac_A{
	meta:
		description = "TrojanDownloader:O97M/Skebpac.A,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d 22 29 } //1 = CreateObject("ADODB.Stream")
		$a_00_1 = {3d 20 22 68 74 74 70 3a 22 20 26 } //1 = "http:" &
		$a_00_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 } //1 = Environ("TMP")
		$a_00_3 = {2e 64 6f 77 6e 6c 6f 61 64 65 72 20 55 52 4c 2c 20 74 6d 70 5f 66 6f 6c 64 65 72 } //1 .downloader URL, tmp_folder
		$a_00_4 = {2e 65 78 65 63 75 74 65 72 20 74 6d 70 5f 66 6f 6c 64 65 72 } //1 .executer tmp_folder
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}