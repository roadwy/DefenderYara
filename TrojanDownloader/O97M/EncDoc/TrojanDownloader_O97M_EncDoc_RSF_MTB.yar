
rule TrojanDownloader_O97M_EncDoc_RSF_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RSF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {6d 6f 72 72 69 73 6c 69 62 72 61 72 79 63 6f 6e 73 75 6c 74 69 6e 67 2e 63 6f 6d 2f 66 61 76 69 63 61 6d 2f 67 65 72 74 6e 6d 2e 70 68 70 90 0a 36 00 68 74 74 70 73 3a 2f 2f 90 00 } //1
		$a_02_1 = {43 3a 5c 68 79 72 64 71 90 02 03 5c 67 77 6e 69 6f 77 90 00 } //1
		$a_00_2 = {6e 66 69 77 70 66 2e 65 78 65 } //1 nfiwpf.exe
		$a_00_3 = {4a 4a 43 43 43 43 4a } //1 JJCCCCJ
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}