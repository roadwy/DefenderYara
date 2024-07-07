
rule TrojanDownloader_Win32_Zlob_gen_AH{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AH,SIGNATURE_TYPE_PEHSTR_EXT,ffffff90 01 2c 01 18 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion
		$a_00_1 = {47 00 65 00 6e 00 65 00 72 00 61 00 74 00 65 00 20 00 4b 00 65 00 79 00 } //2 Generate Key
		$a_00_2 = {41 00 63 00 63 00 65 00 73 00 73 00 20 00 63 00 6f 00 64 00 65 00 3a 00 } //2 Access code:
		$a_00_3 = {56 00 69 00 73 00 69 00 74 00 } //1 Visit
		$a_00_4 = {45 00 6e 00 74 00 65 00 72 00 20 00 57 00 65 00 62 00 73 00 69 00 74 00 65 00 } //2 Enter Website
		$a_00_5 = {43 00 6f 00 70 00 79 00 20 00 4b 00 65 00 79 00 } //2 Copy Key
		$a_01_6 = {53 68 65 6c 6c 5f 4e 6f 74 69 66 79 49 63 6f 6e 41 } //2 Shell_NotifyIconA
		$a_01_7 = {50 72 6f 67 72 61 6d 56 65 72 73 69 6f 6e } //1 ProgramVersion
		$a_00_8 = {56 43 32 30 58 43 30 30 55 } //2 VC20XC00U
		$a_00_9 = {53 00 69 00 74 00 65 00 20 00 63 00 6f 00 64 00 65 00 3a 00 } //2 Site code:
		$a_01_10 = {76 69 73 69 74 65 64 3a } //2 visited:
		$a_00_11 = {53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 } //1 Shell_TrayWnd
		$a_00_12 = {46 69 6e 64 46 69 72 73 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 41 } //10 FindFirstUrlCacheEntryA
		$a_00_13 = {49 6e 74 65 72 6e 65 74 43 72 61 63 6b 55 72 6c 41 } //10 InternetCrackUrlA
		$a_00_14 = {54 72 61 63 6b 50 6f 70 75 70 4d 65 6e 75 45 78 } //10 TrackPopupMenuEx
		$a_01_15 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 58 20 50 61 73 73 77 6f 72 64 20 47 65 6e 65 72 61 74 6f 72 } //75 SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\X Password Generator
		$a_01_16 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 54 79 70 65 64 55 52 4c 73 } //25 Software\Microsoft\Internet Explorer\TypedURLs
		$a_01_17 = {68 74 74 70 3a 2f 2f 77 77 77 2e 78 70 61 73 73 67 65 6e 65 72 61 74 6f 72 2e 63 6f 6d 2f 73 6f 66 74 77 61 72 65 2f } //100 http://www.xpassgenerator.com/software/
		$a_01_18 = {68 74 74 70 3a 2f 2f 35 73 74 61 72 76 69 64 65 6f 73 2e 63 6f 6d 2f 6d 61 69 6e 2f } //100 http://5starvideos.com/main/
		$a_00_19 = {58 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 47 00 65 00 6e 00 65 00 72 00 61 00 74 00 6f 00 72 00 20 00 45 00 72 00 72 00 6f 00 72 00 } //25 X Password Generator Error
		$a_01_20 = {58 20 50 61 73 73 77 6f 72 64 20 47 65 6e 65 72 61 74 6f 72 } //10 X Password Generator
		$a_01_21 = {58 20 50 61 73 73 77 6f 72 64 20 47 65 6e 65 72 61 74 6f 72 20 75 73 61 67 65 20 63 6f 75 6e 74 20 65 78 63 65 65 64 65 64 2c 20 70 6c 65 61 73 65 20 64 6f 77 6e 6c 6f 61 64 20 61 20 6e 65 77 20 76 65 72 73 69 6f 6e 2e } //25 X Password Generator usage count exceeded, please download a new version.
		$a_01_22 = {58 50 61 73 73 47 65 6e 65 72 61 74 6f 72 57 69 6e 64 6f 77 43 6c 61 73 73 } //75 XPassGeneratorWindowClass
		$a_01_23 = {58 20 50 61 73 73 77 6f 72 64 20 47 65 6e 65 72 61 74 6f 72 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 77 61 73 20 63 6f 72 72 75 70 74 65 64 2c 20 70 6c 65 61 73 65 20 72 65 69 6e 73 74 61 6c 6c 20 58 20 50 61 73 73 77 6f 72 64 20 47 65 6e 65 72 61 74 6f 72 2e } //25 X Password Generator installation information was corrupted, please reinstall X Password Generator.
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1+(#a_00_8  & 1)*2+(#a_00_9  & 1)*2+(#a_01_10  & 1)*2+(#a_00_11  & 1)*1+(#a_00_12  & 1)*10+(#a_00_13  & 1)*10+(#a_00_14  & 1)*10+(#a_01_15  & 1)*75+(#a_01_16  & 1)*25+(#a_01_17  & 1)*100+(#a_01_18  & 1)*100+(#a_00_19  & 1)*25+(#a_01_20  & 1)*10+(#a_01_21  & 1)*25+(#a_01_22  & 1)*75+(#a_01_23  & 1)*25) >=300
 
}