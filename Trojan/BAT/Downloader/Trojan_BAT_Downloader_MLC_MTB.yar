
rule Trojan_BAT_Downloader_MLC_MTB{
	meta:
		description = "Trojan:BAT/Downloader.MLC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_1 = {77 61 66 61 61 73 65 78 } //1 wafaasex
		$a_01_2 = {77 73 64 66 } //1 wsdf
		$a_01_3 = {66 64 64 66 64 66 } //1 fddfdf
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_5 = {77 61 6c 61 61 } //1 walaa
		$a_01_6 = {68 74 74 70 73 3a 2f 2f 64 72 69 76 65 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 75 2f 30 2f 75 63 3f 69 64 3d 31 42 30 48 31 7a 65 44 76 53 4e 45 56 74 6f 4f 68 36 63 58 58 63 61 7a 58 35 62 73 70 6f 49 57 70 26 65 78 70 6f 72 74 3d 64 6f 77 6e 6c 6f 61 64 } //1 https://drive.google.com/u/0/uc?id=1B0H1zeDvSNEVtoOh6cXXcazX5bspoIWp&export=download
		$a_01_7 = {00 62 78 78 78 78 78 78 78 78 78 78 78 78 78 00 } //1 戀硸硸硸硸硸硸x
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}