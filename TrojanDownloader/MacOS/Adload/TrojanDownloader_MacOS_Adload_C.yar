
rule TrojanDownloader_MacOS_Adload_C{
	meta:
		description = "TrojanDownloader:MacOS/Adload.C,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {00 00 44 89 c6 48 89 05 c9 13 00 00 48 8d 3d 1a 0c 00 00 ba 01 00 00 00 e8 36 06 00 00 48 8b 0d b1 13 00 00 } //2
		$a_02_1 = {2f 50 4f 53 54 00 [0-20] 65 72 72 6f 72 20 77 68 69 6c 65 20 6d 61 6b 69 6e 67 20 72 65 71 75 65 73 74 3a 20 00 00 00 00 68 74 74 70 3a 2f 2f 6d 2e } //2
		$a_00_2 = {2e 63 6f 6d 2f 67 2f 75 70 3f 6c 66 3d 00 47 45 54 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1) >=5
 
}