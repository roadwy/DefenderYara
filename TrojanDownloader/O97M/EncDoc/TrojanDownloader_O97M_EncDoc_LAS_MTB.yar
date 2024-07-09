
rule TrojanDownloader_O97M_EncDoc_LAS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.LAS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f [0-04] 4a 4a 43 43 42 42 [0-06] 5c 56 69 6a 61 73 65 72 2e 6c 61 73 6a 72 } //1
		$a_01_1 = {4a 45 52 55 49 } //1 JERUI
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 DownloadToFileA
		$a_01_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 } //1 DllRegisterSer
		$a_01_4 = {75 52 6c 4d 6f 6e } //1 uRlMon
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}