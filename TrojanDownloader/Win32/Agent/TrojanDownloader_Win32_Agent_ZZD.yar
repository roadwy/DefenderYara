
rule TrojanDownloader_Win32_Agent_ZZD{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZZD,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 06 00 00 "
		
	strings :
		$a_00_0 = {25 73 5c 4e 74 5f 46 69 6c 65 5f 54 65 6d 70 5c 25 64 2e 74 6d 70 } //10 %s\Nt_File_Temp\%d.tmp
		$a_00_1 = {25 77 69 6e 64 69 72 25 5c 4e 74 5f 46 69 6c 65 5f 54 65 6d 70 5c 6c 69 73 74 2e 74 6d 70 } //10 %windir%\Nt_File_Temp\list.tmp
		$a_00_2 = {4d 49 43 4b 5f 44 4f 57 4e 4c 4f 41 44 5f 4d 55 54 45 58 } //10 MICK_DOWNLOAD_MUTEX
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //10 URLDownloadToFileA
		$a_02_4 = {68 74 74 70 3a 2f 2f 35 31 33 33 38 39 2e 63 6e 2f 90 01 03 2e 74 78 74 90 00 } //1
		$a_02_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 6c 61 6e 67 61 2e 6e 65 74 2f 90 01 03 2e 74 78 74 90 00 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=41
 
}