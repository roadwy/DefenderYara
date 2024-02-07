
rule TrojanDownloader_Win32_Istbar_M{
	meta:
		description = "TrojanDownloader:Win32/Istbar.M,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 4d 75 74 65 78 41 28 69 20 30 2c 20 69 20 30 2c 20 74 20 22 79 73 62 4d 75 74 65 78 22 29 } //01 00  CreateMutexA(i 0, i 0, t "ysbMutex")
		$a_02_1 = {77 77 77 2e 79 73 62 77 65 62 2e 63 6f 6d 2f 69 73 74 2f 90 02 15 2f 69 73 74 64 6f 77 6e 6c 6f 61 64 2e 65 78 65 90 00 } //01 00 
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 49 53 54 } //01 00  Software\IST
		$a_00_3 = {65 78 65 5f 73 74 61 72 74 } //00 00  exe_start
	condition:
		any of ($a_*)
 
}