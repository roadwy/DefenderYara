
rule TrojanDownloader_O97M_Qakbot_RS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.RS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {73 68 6d 6e 63 62 64 2e 63 6f 6d 2f 64 73 2f 32 33 31 31 32 30 2e 67 69 66 90 0a 3f 00 68 74 74 70 73 3a 2f 2f } //1
		$a_03_1 = {6a 75 73 74 68 72 6e 67 2e 63 6f 6d 2f 64 73 2f 32 33 31 31 32 30 2e 67 69 66 90 0a 3f 00 68 74 74 70 73 3a 2f 2f } //1
		$a_03_2 = {63 68 69 63 61 2e 6d 65 64 69 61 2f 64 73 2f 32 33 31 31 32 30 2e 67 69 66 90 0a 3f 00 68 74 74 70 73 3a 2f 2f } //1
		$a_01_3 = {52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //5 RLDownloadToFileA
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*5) >=6
 
}