
rule TrojanDownloader_O97M_Donoff_FD{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FD,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 2e 44 65 63 6f 64 65 64 54 65 78 74 2c 20 73 69 20 2d 20 32 34 30 30 20 2d 20 31 36 } //1 Shell .DecodedText, si - 2400 - 16
		$a_01_1 = {54 68 65 6e 20 53 68 65 6c 6c 20 50 6f 77 5f 53 53 53 2c } //1 Then Shell Pow_SSS,
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_FD_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FD,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 61 74 68 20 3d 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 } //1 path = Environ("temp") &
		$a_03_1 = {68 74 74 70 73 3a 2f 2f 6d 73 6f 66 66 69 63 65 2e 68 6f 73 74 2f ?? ?? ?? 68 6f 73 74 2e 65 78 65 22 2c 20 70 61 74 68 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_FD_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FD,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 2b 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 43 6f 6d 6d 65 6e 74 73 22 29 20 2b } //1  + ActiveDocument.BuiltInDocumentProperties("Comments") +
		$a_01_1 = {56 42 41 2e 53 68 65 6c 6c 24 20 22 22 20 2b 20 } //1 VBA.Shell$ "" + 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_FD_4{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FD,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
		$a_01_1 = {2b 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 75 73 74 6f 6d 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 } //1 + ActiveDocument.CustomDocumentProperties(
		$a_01_2 = {20 2b 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 43 6f 6d 6d 65 6e 74 73 22 29 20 2b } //1  + ActiveDocument.BuiltInDocumentProperties("Comments") +
		$a_01_3 = {56 42 41 2e 53 68 65 6c 6c 24 20 22 22 20 2b 20 } //1 VBA.Shell$ "" + 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}