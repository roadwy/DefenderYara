
rule TrojanDownloader_O97M_Donoff_RE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_03_0 = {31 37 38 2e 31 37 2e 31 37 31 2e 31 34 34 2f 90 0a 2f 00 68 74 74 70 3a 2f 2f } //1
		$a_03_1 = {31 38 35 2e 31 31 37 2e 39 31 2e 31 39 39 2f 90 0a 2f 00 68 74 74 70 3a 2f 2f } //1
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 63 75 70 61 75 64 69 65 6e 63 65 2e 65 78 } //1 C:\Users\Public\Documents\cupaudience.ex
		$a_03_3 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f [0-1f] 2f [0-1f] 2f 73 68 61 78 5f 73 65 72 76 65 72 2e 65 78 65 90 0a 5f 00 68 74 74 70 73 3a 2f 2f } //1
		$a_03_4 = {32 30 39 2e 31 34 31 2e 36 31 2e 31 32 34 2f 90 0a 2f 00 68 74 74 70 3a 2f 2f } //1
		$a_01_5 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 74 68 69 73 64 61 75 67 68 74 65 72 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29 } //1 C:\Users\Public\Documents\thisdaughter.ex" & Chr(101)
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}