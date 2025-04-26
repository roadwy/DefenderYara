
rule TrojanDownloader_O97M_ZLoader_ZLD_MTB{
	meta:
		description = "TrojanDownloader:O97M/ZLoader.ZLD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 32 34 2e 74 6f 70 2f 64 6c 6c 44 64 73 32 32 78 64 73 64 66 37 38 2f 78 6c 73 70 2e 63 31 30 } //1 https://download24.top/dllDds22xdsdf78/xlsp.c10
		$a_01_1 = {43 3a 5c 75 4f 57 4d 72 6d 6e 5c 6c 71 62 55 63 47 68 5c 42 4b 69 50 73 49 6f 2e 64 6c 6c } //1 C:\uOWMrmn\lqbUcGh\BKiPsIo.dll
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}