
rule TrojanDownloader_O97M_Donoff_PFN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PFN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_01_1 = {53 68 65 6c 6c 24 20 77 70 72 6f 63 43 58 6d 51 2c 20 30 } //1 Shell$ wprocCXmQ, 0
		$a_01_2 = {4d 69 64 28 77 57 46 73 49 59 58 44 45 45 6f 2c 20 31 33 2c 20 37 33 29 } //1 Mid(wWFsIYXDEEo, 13, 73)
		$a_01_3 = {3d 20 41 72 72 61 79 28 22 76 52 41 70 6c 57 41 42 22 2c 20 22 63 59 4c 69 4c 76 5a 77 22 2c 20 22 7a 5a 57 59 49 46 55 58 22 2c 20 22 69 45 54 45 68 54 71 48 22 2c 20 22 6a 4b 5a 6f 44 56 6c 64 22 29 } //1 = Array("vRAplWAB", "cYLiLvZw", "zZWYIFUX", "iETEhTqH", "jKZoDVld")
		$a_01_4 = {3d 20 22 55 6b 4a 73 57 54 50 7a 49 73 56 35 6e 69 33 30 50 7a 4b 5a 32 4c 64 4f 44 45 50 58 6a 46 42 69 66 69 58 48 6b 57 72 4a 44 63 45 7a 49 45 51 4f 43 4d 6e 76 43 49 6c 58 68 59 64 54 42 5a 50 4c 55 76 4e 51 58 6c 59 4d 75 6a 4c 77 70 7a 77 71 49 4c 69 42 53 46 63 57 7a 7a 5a 4d 74 59 49 64 4e 73 64 4d 71 41 72 51 6f 61 42 54 77 6d 68 69 5a 6e 4c 70 33 62 22 } //1 = "UkJsWTPzIsV5ni30PzKZ2LdODEPXjFBifiXHkWrJDcEzIEQOCMnvCIlXhYdTBZPLUvNQXlYMujLwpzwqILiBSFcWzzZMtYIdNsdMqArQoaBTwmhiZnLp3b"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}