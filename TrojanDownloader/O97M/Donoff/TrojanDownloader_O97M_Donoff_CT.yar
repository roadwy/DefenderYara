
rule TrojanDownloader_O97M_Donoff_CT{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CT,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Sub Document_Open()
		$a_00_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 } //1 CreateObject("Scripting.FileSystemObject
		$a_00_2 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 6a 73 2c 20 54 72 75 65 29 } //1 .CreateTextFile(js, True)
		$a_02_3 = {45 78 70 61 6e 64 45 6e [0-20] 76 69 72 6f 6e 6d 65 6e 74 53 [0-20] 25 54 45 4d 50 25 } //1
		$a_00_4 = {53 68 65 6c 6c 20 22 77 73 63 72 69 70 74 } //1 Shell "wscript
		$a_02_5 = {61 74 68 61 6e 6b 61 72 61 [0-20] 69 6b 61 62 61 64 64 69 2e 69 6e [0-20] 6c 79 62 79 62 69 72 64 69 65 2e } //1
		$a_02_6 = {63 68 2e 6e 61 76 69 74 [0-20] 65 6c 69 61 2e 63 6f 6d 20 63 61 72 73 67 [0-20] 61 6d 65 73 2e 6f 72 67 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1+(#a_02_6  & 1)*1) >=6
 
}