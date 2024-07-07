
rule TrojanDownloader_Win32_Mydown_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Mydown.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0e 00 08 00 00 "
		
	strings :
		$a_00_0 = {6d 77 69 6e 73 79 73 2e 69 6e 69 } //1 mwinsys.ini
		$a_00_1 = {64 6c 6c 5f 68 69 74 70 6f 70 } //1 dll_hitpop
		$a_00_2 = {64 6c 6c 5f 73 74 61 72 74 } //1 dll_start
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 72 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\run
		$a_00_4 = {6d 79 64 6f 77 6e } //1 mydown
		$a_00_5 = {63 68 65 63 6b 63 6a } //1 checkcj
		$a_00_6 = {79 6d 61 6e 74 65 63 20 41 6e 74 69 56 69 72 75 73 00 00 00 ff ff ff ff 01 00 00 00 53 00 00 00 ff ff ff ff 04 00 00 00 6f 64 33 32 } //3
		$a_03_7 = {8b 4d fc 8a 4c 11 ff 8b 75 ec 88 0c 1e 43 42 48 75 ee 8b 45 f8 e8 90 01 04 85 c0 7e 17 ba 01 00 00 00 8b 4d f8 8a 4c 11 ff 8b 75 ec 88 0c 1e 43 42 48 75 ee 90 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*3+(#a_03_7  & 1)*10) >=14
 
}