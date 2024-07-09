
rule TrojanDownloader_O97M_Bartallex_AD_MSR{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.AD!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 6d 61 72 65 6e 64 6f 67 65 72 2e 63 6f 6d } //1 https://marendoger.com
		$a_03_1 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 22 50 69 63 74 75 72 65 [0-03] 22 29 } //1
		$a_01_2 = {43 53 74 72 28 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 } //1 CStr(Environ("APPDATA")
		$a_01_3 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}