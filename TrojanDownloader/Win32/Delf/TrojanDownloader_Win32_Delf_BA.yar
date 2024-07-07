
rule TrojanDownloader_Win32_Delf_BA{
	meta:
		description = "TrojanDownloader:Win32/Delf.BA,SIGNATURE_TYPE_PEHSTR_EXT,7d 00 7d 00 1a 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //100 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {5c 68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 \http\shell\open\command
		$a_00_2 = {74 72 6f 6a 61 6e } //1 trojan
		$a_00_3 = {73 70 79 77 61 72 65 } //1 spyware
		$a_00_4 = {68 69 6a 61 63 6b } //1 hijack
		$a_00_5 = {6b 69 6c 6c 62 6f 78 } //1 killbox
		$a_00_6 = {77 69 6e 33 32 64 65 6c 66 6b 69 6c } //1 win32delfkil
		$a_00_7 = {63 6f 6d 62 6f 66 69 78 } //1 combofix
		$a_00_8 = {77 69 6e 33 32 64 65 6c 66 } //1 win32delf
		$a_00_9 = {67 6f 6f 67 6c 65 62 6f 74 } //1 googlebot
		$a_00_10 = {64 6f 77 6e 20 66 69 6c 65 7a 3a 20 70 6f 72 61 20 6b 61 63 68 61 74 6a 20 66 69 6c 65 20 23 } //1 down filez: pora kachatj file #
		$a_00_11 = {74 5f 77 6f 72 6b 5f 70 72 6f 63 61 3b 20 74 69 6d 65 72 32 5f 77 6f 72 6b 5f 74 69 6d 65 6f 75 74 3d } //1 t_work_proca; timer2_work_timeout=
		$a_00_12 = {5c 73 79 73 74 65 6d 33 32 5c 72 65 67 73 76 72 33 32 2e 65 78 65 } //1 \system32\regsvr32.exe
		$a_00_13 = {64 6f 77 6e 20 63 6f 6e 66 3a 20 70 6f 72 61 20 6b 61 63 68 61 74 6a 21 } //1 down conf: pora kachatj!
		$a_02_14 = {68 74 74 70 3a 2f 2f 90 02 20 2f 68 6b 2f 67 65 74 63 90 02 04 2e 70 68 70 90 00 } //1
		$a_00_15 = {64 6f 77 6e 20 63 6f 6e 66 3a 20 76 72 6f 64 65 20 6f 6b 20 3d } //1 down conf: vrode ok =
		$a_00_16 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 } //1 \SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
		$a_00_17 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 61 72 65 64 54 61 73 6b 53 63 68 65 64 75 6c 65 72 } //1 \SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler
		$a_00_18 = {5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 65 73 73 69 6f 6e 20 4d 61 6e 61 67 65 72 } //1 \SYSTEM\CurrentControlSet\Control\Session Manager
		$a_00_19 = {50 65 6e 64 69 6e 67 46 69 6c 65 52 65 6e 61 6d 65 4f 70 65 72 61 74 69 6f 6e 73 } //1 PendingFileRenameOperations
		$a_00_20 = {68 6b 31 2e 30 2e 30 2e 31 } //1 hk1.0.0.1
		$a_00_21 = {64 6f 75 62 6c 65 5f 68 6f 6f 6b 61 2e 64 6c 6c } //1 double_hooka.dll
		$a_00_22 = {48 54 54 50 2f 31 2e 30 } //1 HTTP/1.0
		$a_00_23 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //1 Content-Type: application/x-www-form-urlencoded
		$a_02_24 = {b3 01 6a 00 6a 00 6a 00 6a 03 68 90 01 09 89 45 e4 8b 45 f4 ba 90 01 09 0f 85 90 01 04 6a 00 6a 00 6a 03 68 90 01 04 68 90 01 04 6a 50 8b 45 d4 e8 90 01 04 50 8b 45 e4 50 e8 90 01 04 89 45 e8 6a 00 68 00 00 00 80 6a 00 68 90 01 04 68 90 01 04 8b 45 d0 e8 90 01 04 50 8b 45 f4 e8 90 01 04 50 8b 45 e8 50 e8 90 01 04 8b f0 8d 45 d8 90 00 } //1
		$a_02_25 = {8b 45 cc 50 8d 45 e8 50 8d 45 c4 e8 90 01 04 ff 75 c4 68 90 01 04 ff 75 f0 8d 45 c8 ba 03 00 00 00 e8 90 01 04 8b 55 c8 b9 90 01 04 b8 90 01 04 e8 90 01 04 a1 90 01 04 ff 30 68 90 01 04 ff 75 f0 68 90 01 04 8d 45 c0 ba 04 00 00 00 e8 90 01 04 8b 45 c0 e8 90 01 04 50 e8 90 00 } //1
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_02_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1+(#a_00_18  & 1)*1+(#a_00_19  & 1)*1+(#a_00_20  & 1)*1+(#a_00_21  & 1)*1+(#a_00_22  & 1)*1+(#a_00_23  & 1)*1+(#a_02_24  & 1)*1+(#a_02_25  & 1)*1) >=125
 
}