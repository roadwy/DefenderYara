
rule TrojanDownloader_Linux_Donoff_gen_A{
	meta:
		description = "TrojanDownloader:Linux/Donoff.gen!A,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 } //1 "urlmon" Alias 
		$a_00_1 = {22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 } //1 "shell32.dll" Alias 
		$a_00_2 = {43 68 61 6e 67 65 54 65 78 74 } //1 ChangeText
		$a_00_3 = {43 68 61 6e 67 65 4e 75 6d 62 65 72 } //1 ChangeNumber
		$a_00_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 61 2c 20 62 2c 20 30 2c 20 30 } //1 URLDownloadToFile 0, a, b, 0, 0
		$a_00_5 = {22 62 6c 61 68 90 01 01 2e 65 78 65 22 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}