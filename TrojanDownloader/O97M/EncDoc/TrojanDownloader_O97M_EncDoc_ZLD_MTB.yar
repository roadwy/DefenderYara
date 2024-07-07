
rule TrojanDownloader_O97M_EncDoc_ZLD_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ZLD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 32 30 35 2e 31 38 35 2e 31 31 33 2e 32 30 2f 50 52 54 4b 66 4e 30 } //1 http://205.185.113.20/PRTKfN0
		$a_01_1 = {68 74 74 70 3a 2f 2f 32 30 35 2e 31 38 35 2e 31 31 33 2e 32 30 2f 59 76 47 58 44 36 63 44 } //1 http://205.185.113.20/YvGXD6cD
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}