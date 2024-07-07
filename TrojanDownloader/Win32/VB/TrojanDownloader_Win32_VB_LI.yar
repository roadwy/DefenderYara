
rule TrojanDownloader_Win32_VB_LI{
	meta:
		description = "TrojanDownloader:Win32/VB.LI,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_01_0 = {4a 00 53 00 49 00 4b 00 4a 00 49 00 4b 00 39 00 35 00 32 00 34 00 } //10 JSIKJIK9524
		$a_01_1 = {6d 6f 64 5f 56 61 72 69 61 76 65 69 73 00 00 00 73 6d 63 66 67 00 00 00 10 00 00 00 4a 00 53 00 48 00 4e 00 46 00 49 00 55 00 59 00 } //1
		$a_01_2 = {6d 6f 64 5f 45 6e 63 72 69 70 74 00 10 00 00 00 4a 00 53 00 48 00 4e 00 46 00 49 00 55 00 59 00 } //1
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //10 URLDownloadToFileA
		$a_00_4 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //10 MSVBVM60.DLL
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10) >=31
 
}