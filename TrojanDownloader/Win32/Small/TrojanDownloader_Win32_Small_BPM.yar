
rule TrojanDownloader_Win32_Small_BPM{
	meta:
		description = "TrojanDownloader:Win32/Small.BPM,SIGNATURE_TYPE_PEHSTR_EXT,25 00 24 00 13 00 00 "
		
	strings :
		$a_00_0 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 70 75 69 64 2e 73 79 73 } //1 %SystemRoot%\system32\drivers\puid.sys
		$a_00_1 = {5c 64 72 69 76 65 72 73 5c 44 65 65 70 46 72 7a 2e 73 79 73 } //1 \drivers\DeepFrz.sys
		$a_00_2 = {5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //1 \.\PhysicalDrive0
		$a_00_3 = {5c 2e 5c 50 68 79 73 69 63 61 6c 48 61 72 64 44 69 73 6b 30 } //1 \.\PhysicalHardDisk0
		$a_00_4 = {5c 44 6f 73 44 65 76 69 63 65 73 5c 50 68 79 73 69 63 61 6c 48 61 72 64 44 69 73 6b 30 } //1 \DosDevices\PhysicalHardDisk0
		$a_00_5 = {5c 44 65 76 69 63 65 5c 48 61 72 64 64 69 73 6b 30 5c 44 52 30 } //1 \Device\Harddisk0\DR0
		$a_00_6 = {61 6e 74 69 61 72 70 2e 65 78 65 } //1 antiarp.exe
		$a_00_7 = {33 36 30 74 72 61 79 2e 65 78 65 } //1 360tray.exe
		$a_00_8 = {33 36 30 53 61 66 65 2e 65 78 65 } //1 360Safe.exe
		$a_00_9 = {5c 6d 73 67 71 75 65 75 65 6c 69 73 74 2e 65 78 65 } //1 \msgqueuelist.exe
		$a_00_10 = {75 73 65 72 69 6e 69 74 2e 65 78 65 } //1 userinit.exe
		$a_00_11 = {5c 73 70 6f 6f 6c 73 76 2e 65 78 65 } //1 \spoolsv.exe
		$a_00_12 = {6e 74 66 73 2e 64 6c 6c } //1 ntfs.dll
		$a_00_13 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 } //1 ntoskrnl.exe
		$a_00_14 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_00_15 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 72 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\run
		$a_00_16 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_02_17 = {8d 85 f4 fb ff ff 50 e8 90 01 02 ff ff 8d 85 f4 fb ff ff c7 04 24 90 01 02 40 00 50 e8 90 01 02 00 00 59 8d 85 f4 fb ff ff 59 53 50 8d 85 e8 f8 ff ff 50 ff 15 90 01 04 8d 85 e8 f8 ff ff 50 ff 15 90 01 04 8d 45 f8 50 68 90 01 02 40 00 68 02 00 00 80 ff 15 90 01 04 85 c0 75 27 8d 85 f4 fb ff ff 50 e8 90 01 02 00 00 59 40 50 8d 85 f4 fb ff ff 50 6a 01 53 90 00 } //10
		$a_02_18 = {eb 00 b9 00 01 00 00 ba b1 c9 ec cc 8d 41 ff 51 b9 08 00 00 00 d1 e8 73 02 33 c2 49 75 f7 59 89 04 8d 90 01 02 40 00 49 75 e3 c3 90 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_02_17  & 1)*10+(#a_02_18  & 1)*10) >=36
 
}