
rule TrojanDownloader_O97M_Donoff_PL{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PL,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {78 48 74 74 70 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 } //1 xHttp.Open "GET", "http
		$a_02_1 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 90 02 10 2e 65 78 65 90 00 } //1
		$a_02_2 = {53 68 65 6c 6c 20 28 22 90 02 10 2e 65 78 65 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}