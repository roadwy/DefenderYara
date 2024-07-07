
rule TrojanDownloader_O97M_Emotet_PDH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 6f 72 6f 61 6e 64 64 65 6e 74 61 6c 63 61 72 65 63 65 6e 74 65 72 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 30 4a 52 49 32 73 4f 56 70 4e 6b 44 68 41 65 2f } //1 ://oroanddentalcarecenter.com/wp-includes/0JRI2sOVpNkDhAe/
		$a_01_1 = {3a 2f 2f 64 65 76 2e 73 75 62 73 32 6d 65 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 45 4d 61 2f } //1 ://dev.subs2me.com/wp-includes/EMa/
		$a_01_2 = {3a 2f 2f 69 6d 61 67 65 63 61 72 65 70 68 6f 74 6f 67 72 61 70 68 79 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 4b 56 52 76 55 79 61 74 30 71 71 4b 30 57 2f } //1 ://imagecarephotography.com/wp-includes/KVRvUyat0qqK0W/
		$a_01_3 = {3a 2f 2f 79 61 6e 61 70 69 72 69 2e 63 6f 6d 2f 75 70 65 61 74 76 2f 39 49 5a 50 39 52 66 62 48 33 33 38 70 46 50 49 2f } //1 ://yanapiri.com/upeatv/9IZP9RfbH338pFPI/
		$a_01_4 = {3a 2f 2f 67 75 72 6d 69 74 6a 61 73 77 61 6c 2e 63 61 2f 66 72 65 72 2d 68 61 74 65 2f 4c 57 33 37 65 72 77 53 41 68 67 55 2f } //1 ://gurmitjaswal.ca/frer-hate/LW37erwSAhgU/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}