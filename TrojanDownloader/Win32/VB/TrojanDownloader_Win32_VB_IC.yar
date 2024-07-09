
rule TrojanDownloader_Win32_VB_IC{
	meta:
		description = "TrojanDownloader:Win32/VB.IC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 56 42 39 38 5c 56 42 36 2e 4f 4c 42 } //1 C:\Program Files\Microsoft Visual Studio\VB98\VB6.OLB
		$a_00_1 = {32 74 6e 65 74 70 6b } //1 2tnetpk
		$a_00_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_03_3 = {74 00 2e 00 6e 00 65 00 74 00 70 00 6b 00 2e 00 63 00 6e 00 2f 00 73 00 6f 00 66 00 74 00 2f 00 31 00 2f 00 [0-02] 2e 00 65 00 78 00 65 00 } //1
		$a_02_4 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 61 00 62 00 35 00 [0-04] 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}