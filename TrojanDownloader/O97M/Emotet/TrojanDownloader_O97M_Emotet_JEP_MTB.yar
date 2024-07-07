
rule TrojanDownloader_O97M_Emotet_JEP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.JEP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4a 4a 43 43 42 42 } //1 JJCCBB
		$a_01_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 72 65 67 73 76 72 33 32 2e 65 78 65 } //1 C:\Windows\System32\regsvr32.exe
		$a_01_2 = {2e 6f 6f 63 63 78 78 } //1 .ooccxx
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}