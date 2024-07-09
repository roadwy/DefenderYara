
rule TrojanDownloader_Win32_Banload_AKZ{
	meta:
		description = "TrojanDownloader:Win32/Banload.AKZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-20] 68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f 37 33 31 36 32 36 31 31 [0-20] 2e 73 77 66 [0-20] 2e 65 78 65 } //1
		$a_01_1 = {54 61 73 6b 62 61 72 43 72 65 61 74 65 64 } //1 TaskbarCreated
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}