
rule TrojanDownloader_O97M_Donoff_YI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.YI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 35 31 2e 32 35 35 2e 31 35 35 2e 31 2f 70 61 67 65 73 2f 66 69 6c 65 63 6c 6f 75 64 2f 35 65 32 64 37 62 31 33 30 63 66 34 66 65 62 30 33 30 32 33 65 35 38 30 62 33 34 33 32 66 61 39 64 37 31 64 37 38 33 38 2e 65 78 65 } //1 http://51.255.155.1/pages/filecloud/5e2d7b130cf4feb03023e580b3432fa9d71d7838.exe
		$a_01_1 = {4f 62 6a 65 63 74 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 Object = CreateObject("WScript.Shell")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}