
rule TrojanDownloader_O97M_Donoff_CU{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CU,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 25 54 [0-0f] 4d [0-0f] 50 [0-0f] 2b 20 90 1d 0f 00 20 2b [0-0f] 78 [0-ff] 53 68 65 6c 6c 20 90 12 0f 00 2e 90 12 0f 00 2e 43 61 70 74 69 6f 6e 20 2b 90 0a ff 00 90 1b 03 20 3d 20 22 25 5c 90 12 0f 00 2e 65 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_CU_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CU,SIGNATURE_TYPE_MACROHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_01_0 = {2b 20 22 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 22 20 2b } //3 + " (New-Object S" +
		$a_01_1 = {4d 73 67 42 6f 78 20 22 57 6f 72 64 20 68 61 73 20 65 6e 63 6f 75 6e 74 65 72 65 64 20 61 20 70 72 6f 62 6c 65 6d 22 2c 20 31 36 2c 20 22 } //3 MsgBox "Word has encountered a problem", 16, "
		$a_01_2 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 25 54 4d 50 25 5c 71 77 65 72 2e 65 78 65 27 3b 22 2c 20 30 } //4 Start-Process '%TMP%\qwer.exe';", 0
		$a_01_3 = {2b 20 22 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 22 20 2b } //3 + ").DownloadFile('" +
		$a_01_4 = {2b 20 22 63 62 6b 2e 6d 64 6b 27 2c 27 25 54 4d 50 25 5c 71 77 65 72 2e 65 78 65 27 29 3b } //5 + "cbk.mdk','%TMP%\qwer.exe');
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*4+(#a_01_3  & 1)*3+(#a_01_4  & 1)*5) >=18
 
}