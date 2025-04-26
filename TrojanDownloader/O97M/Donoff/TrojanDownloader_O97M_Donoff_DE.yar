
rule TrojanDownloader_O97M_Donoff_DE{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DE,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {4d 6f 76 65 64 50 65 72 6d 61 6e 65 6e 74 6c 79 20 3d 20 53 70 6c 69 74 28 22 } //1 MovedPermanently = Split("
		$a_00_1 = {26 20 22 2c 73 79 6d 22 2c 20 76 62 48 69 64 65 } //1 & ",sym", vbHide
		$a_00_2 = {31 73 51 76 4e 6b 48 49 34 78 59 44 41 56 73 6a 78 52 53 41 4f 71 74 47 53 47 57 69 74 4d 5a 44 22 } //1 1sQvNkHI4xYDAVsjxRSAOqtGSGWitMZD"
		$a_00_3 = {2b 20 22 5c 68 75 6d 73 72 65 61 22 20 2b } //1 + "\humsrea" +
		$a_00_4 = {53 68 65 6c 6c 20 52 6f 62 6f 62 6f 62 20 26 20 } //1 Shell Robobob & 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}