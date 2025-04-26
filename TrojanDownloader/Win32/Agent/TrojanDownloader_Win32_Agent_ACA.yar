
rule TrojanDownloader_Win32_Agent_ACA{
	meta:
		description = "TrojanDownloader:Win32/Agent.ACA,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 0c 00 00 "
		
	strings :
		$a_01_0 = {38 35 2e 31 37 2e 36 30 2e } //10 85.17.60.
		$a_01_1 = {76 6d 63 5f 72 61 5f 75 65 } //10 vmc_ra_ue
		$a_00_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_3 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_4 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //1 HttpSendRequestA
		$a_01_5 = {53 74 72 43 6d 70 4e 49 57 } //1 StrCmpNIW
		$a_01_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_00_7 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //1 CreateProcessA
		$a_01_8 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 42 } //1 rundll32.exe "%s",B
		$a_01_9 = {4c 6f 61 64 41 70 70 49 6e 69 74 5f 44 4c 4c 73 } //1 LoadAppInit_DLLs
		$a_01_10 = {70 6f 70 75 70 00 } //1 潰異p
		$a_01_11 = {64 6f 77 6e 6c 6f 61 64 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=30
 
}