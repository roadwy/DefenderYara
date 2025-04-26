
rule TrojanDownloader_Win32_QQHelper_gen_A{
	meta:
		description = "TrojanDownloader:Win32/QQHelper.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,12 00 0f 00 13 00 00 "
		
	strings :
		$a_00_0 = {8b 46 14 8b 4e 18 2b c7 83 c4 0c 83 f9 10 89 46 14 72 02 8b 1b c6 04 03 00 5b } //3
		$a_00_1 = {89 41 08 8b 4b 04 89 48 04 8a 53 14 8a 48 14 88 50 14 88 4b 14 80 7b 14 01 } //3
		$a_00_2 = {89 41 08 8b 4b 04 89 48 04 8a 53 0e 8a 48 0e 88 50 0e 88 4b 0e 80 7b 0e 01 } //3
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //1 Software\Microsoft\Internet Explorer\Main
		$a_00_4 = {43 55 52 52 45 4e 54 5f 55 53 45 52 } //1 CURRENT_USER
		$a_00_5 = {53 74 61 72 74 20 50 61 67 65 } //1 Start Page
		$a_00_6 = {45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //1 Explorer_Server
		$a_00_7 = {75 70 64 61 74 65 2e 64 61 74 } //1 update.dat
		$a_00_8 = {57 69 6e 64 6f 77 73 55 70 64 61 74 65 } //1 WindowsUpdate
		$a_00_9 = {68 6f 6d 65 70 61 67 65 } //1 homepage
		$a_00_10 = {75 72 6c 66 6f 6c 64 65 72 } //1 urlfolder
		$a_00_11 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4c 61 6d 70 } //1 HKEY_LOCAL_MACHINE\SOFTWARE\Lamp
		$a_00_12 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_13 = {4b 69 6c 6c 20 57 69 6e 64 6f 77 20 46 61 69 6c 65 64 } //1 Kill Window Failed
		$a_00_14 = {4b 69 6c 6c 20 57 69 6e 64 6f 77 20 53 75 63 63 65 73 73 } //1 Kill Window Success
		$a_00_15 = {2d 6b 69 6c 6c } //1 -kill
		$a_00_16 = {4e 6f 74 20 52 75 6e } //1 Not Run
		$a_00_17 = {48 61 73 20 52 75 6e } //1 Has Run
		$a_01_18 = {74 00 76 00 67 00 75 00 69 00 64 00 65 00 2e 00 70 00 70 00 73 00 2e 00 74 00 76 00 } //-50 tvguide.pps.tv
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1+(#a_01_18  & 1)*-50) >=15
 
}