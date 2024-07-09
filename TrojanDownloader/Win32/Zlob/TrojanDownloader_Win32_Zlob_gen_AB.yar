
rule TrojanDownloader_Win32_Zlob_gen_AB{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff9b 01 ffffff9b 01 09 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //100 InternetOpenUrlA
		$a_00_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //100 ShellExecuteA
		$a_01_2 = {53 68 65 6c 6c 5f 4e 6f 74 69 66 79 49 63 6f 6e 41 } //100 Shell_NotifyIconA
		$a_00_3 = {44 69 73 70 6c 61 79 49 63 6f 6e } //100 DisplayIcon
		$a_01_4 = {74 6d 78 78 78 68 2e 64 6c 6c } //10 tmxxxh.dll
		$a_00_5 = {62 6c 6f 77 6a 6f 62 2e } //10 blowjob.
		$a_01_6 = {73 79 73 74 65 6d 20 6f 6e 20 63 6f 6d 70 75 74 65 72 20 69 73 20 64 61 6d 61 67 65 64 2e } //1 system on computer is damaged.
		$a_01_7 = {56 69 72 75 73 } //1 Virus
		$a_01_8 = {69 6e 66 65 63 74 65 64 } //1 infected
	condition:
		((#a_01_0  & 1)*100+(#a_00_1  & 1)*100+(#a_01_2  & 1)*100+(#a_00_3  & 1)*100+(#a_01_4  & 1)*10+(#a_00_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=411
 
}
rule TrojanDownloader_Win32_Zlob_gen_AB_2{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff9b 01 ffffff9b 01 09 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //100 InternetOpenUrlA
		$a_00_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //100 ShellExecuteA
		$a_01_2 = {53 68 65 6c 6c 5f 4e 6f 74 69 66 79 49 63 6f 6e 41 } //100 Shell_NotifyIconA
		$a_00_3 = {44 69 73 70 6c 61 79 49 63 6f 6e } //100 DisplayIcon
		$a_02_4 = {61 6e 61 6c [0-0a] 6d 6f 6e 73 74 65 72 73 2e 63 6f 6d } //10
		$a_01_5 = {2f 6d 61 74 75 72 65 2e 5f 78 65 } //10 /mature._xe
		$a_01_6 = {73 79 73 74 65 6d 20 6f 6e 20 63 6f 6d 70 75 74 65 72 20 69 73 20 64 61 6d 61 67 65 64 2e } //1 system on computer is damaged.
		$a_01_7 = {56 69 72 75 73 } //1 Virus
		$a_01_8 = {69 6e 66 65 63 74 65 64 } //1 infected
	condition:
		((#a_01_0  & 1)*100+(#a_00_1  & 1)*100+(#a_01_2  & 1)*100+(#a_00_3  & 1)*100+(#a_02_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=411
 
}