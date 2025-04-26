
rule TrojanDownloader_O97M_Donoff_YJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.YJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 35 31 2e 32 35 35 2e 31 35 35 2e 31 2f 70 61 67 65 73 2f 66 69 6c 65 63 6c 6f 75 64 2f 35 65 32 64 37 62 31 33 30 63 66 34 66 65 62 30 33 30 32 33 65 35 38 30 62 33 34 33 32 66 61 39 64 37 31 64 37 38 33 38 2e 65 78 65 } //1 http://51.255.155.1/pages/filecloud/5e2d7b130cf4feb03023e580b3432fa9d71d7838.exe
		$a_00_1 = {45 6e 76 69 72 6f 6e 24 28 22 74 6d 70 2f 66 69 6c 65 6e 61 6d 65 2e 65 78 65 22 29 } //1 Environ$("tmp/filename.exe")
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}