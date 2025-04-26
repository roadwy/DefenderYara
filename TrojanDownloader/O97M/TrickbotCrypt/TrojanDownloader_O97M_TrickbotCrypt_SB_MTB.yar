
rule TrojanDownloader_O97M_TrickbotCrypt_SB_MTB{
	meta:
		description = "TrojanDownloader:O97M/TrickbotCrypt.SB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_00_0 = {6f 70 65 6e 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 64 6f 74 2e 6a 70 65 67 } //5 open"c:\programdata\dot.jpeg
		$a_00_1 = {73 75 62 6d 6f 6f 6e 6c 69 67 68 74 28 29 } //1 submoonlight()
		$a_00_2 = {77 6f 72 6b 73 68 65 65 74 73 28 22 74 61 62 6c 65 6f 66 63 6f 6e 74 65 6e 74 22 29 } //1 worksheets("tableofcontent")
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=7
 
}
rule TrojanDownloader_O97M_TrickbotCrypt_SB_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/TrickbotCrypt.SB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {2e 63 72 65 61 74 65 74 65 78 74 66 69 6c 65 28 22 63 3a 5c [0-20] 5c [0-20] 2e 76 62 22 2b 22 73 22 29 } //1
		$a_02_1 = {2e 63 72 65 61 74 65 66 6f 6c 64 65 72 28 22 63 3a 5c [0-20] 5c [0-20] 22 29 } //1
		$a_02_2 = {2e 65 78 65 63 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 63 3a 5c [0-20] 5c [0-20] 2e 76 62 22 2b 22 73 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}