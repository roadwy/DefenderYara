
rule TrojanDownloader_Win32_Banload_AWI{
	meta:
		description = "TrojanDownloader:Win32/Banload.AWI,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 04 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 0f b6 44 30 ff 33 c3 89 45 e0 3b 7d e0 7c 0f 8b 45 e0 } //01 00 
		$a_01_1 = {5c 63 6d 64 2e 65 78 65 20 2f 6b 20 72 65 67 73 76 72 33 32 2e 65 78 65 20 20 22 } //01 00  \cmd.exe /k regsvr32.exe  "
		$a_01_2 = {61 70 6c 69 63 61 74 69 76 6f 73 5c } //01 00  aplicativos\
		$a_01_3 = {32 2e 6a 70 67 22 } //01 00  2.jpg"
		$a_01_4 = {35 2e 63 70 6c } //00 00  5.cpl
		$a_00_5 = {78 66 00 00 0c } //00 0c 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Banload_AWI_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.AWI,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {35 2e 63 70 6c 90 01 0b 32 2e 74 78 74 90 01 0b 32 2e 6a 70 67 90 00 } //01 00 
		$a_02_1 = {4f 4e 5c 52 55 4e 90 01 0a 00 3a 5c 57 69 6e 64 6f 77 73 5c 53 90 00 } //01 00 
		$a_00_2 = {00 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 00 } //01 00  愀慴剜慯業杮\
		$a_00_3 = {54 63 61 62 65 63 61 64 6f 6d 65 75 70 61 75 } //00 00  Tcabecadomeupau
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}