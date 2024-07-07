
rule TrojanDownloader_O97M_EncDoc_PI_MSR{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PI!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 69 6e 64 6f 77 73 69 6e 73 74 61 6c 6c 65 72 2e 69 6e 73 74 61 6c 6c 65 72 22 29 } //createobject("windowsinstaller.installer")  1
		$a_80_1 = {2e 69 6e 73 74 61 6c 6c 70 72 6f 64 75 63 74 22 68 74 74 70 3a 2f 2f 34 35 2e 31 34 37 2e 32 32 39 2e 39 31 } //.installproduct"http://45.147.229.91  1
		$a_80_2 = {73 75 62 61 75 74 6f 5f 6f 70 65 6e 28 29 } //subauto_open()  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}