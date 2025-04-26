
rule TrojanDownloader_Win32_FakeMSA_gen_A{
	meta:
		description = "TrojanDownloader:Win32/FakeMSA.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,5f 00 5a 00 0a 00 00 "
		
	strings :
		$a_00_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //20 URLDownloadToFileA
		$a_00_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //20 ShellExecuteA
		$a_01_2 = {56 42 41 36 2e 44 4c 4c } //20 VBA6.DLL
		$a_01_3 = {45 56 45 4e 54 5f 53 49 4e 4b 5f 51 75 65 72 79 49 6e 74 65 72 66 61 63 65 } //20 EVENT_SINK_QueryInterface
		$a_01_4 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 41 00 64 00 76 00 69 00 73 00 65 00 72 00 } //5 Microsoft Security Adviser
		$a_01_5 = {2f 00 6f 00 75 00 74 00 2e 00 70 00 68 00 70 00 } //5 /out.php
		$a_01_6 = {64 00 77 00 6e 00 6c 00 64 00 72 00 2e 00 65 00 78 00 65 00 } //5 dwnldr.exe
		$a_01_7 = {41 00 6e 00 74 00 69 00 76 00 69 00 72 00 58 00 50 00 30 00 38 00 } //5 AntivirXP08
		$a_01_8 = {6d 00 73 00 73 00 61 00 64 00 76 00 } //5 mssadv
		$a_01_9 = {6d 00 73 00 63 00 74 00 72 00 6c 00 } //5 msctrl
	condition:
		((#a_00_0  & 1)*20+(#a_00_1  & 1)*20+(#a_01_2  & 1)*20+(#a_01_3  & 1)*20+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5+(#a_01_8  & 1)*5+(#a_01_9  & 1)*5) >=90
 
}