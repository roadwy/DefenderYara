
rule TrojanDownloader_O97M_EncDoc_ZLS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ZLS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 49 44 44 43 48 72 6b 5c 72 57 77 69 79 43 46 5c 49 59 46 4c 65 6d 62 2e 64 6c 6c } //1 C:\IDDCHrk\rWwiyCF\IYFLemb.dll
		$a_01_1 = {43 3a 5c 6f 70 6e 73 64 6b 72 5c 49 6a 69 79 6f 71 69 5c 4b 71 77 51 59 4f 74 2e 65 78 65 } //1 C:\opnsdkr\Ijiyoqi\KqwQYOt.exe
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_3 = {72 65 67 73 76 72 33 32 2e 65 78 65 } //1 regsvr32.exe
		$a_01_4 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //1 rundll32.exe
		$a_01_5 = {4a 4a 43 43 4a 4a } //1 JJCCJJ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}