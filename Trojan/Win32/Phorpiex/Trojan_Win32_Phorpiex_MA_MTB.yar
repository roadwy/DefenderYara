
rule Trojan_Win32_Phorpiex_MA_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {c7 85 2c f4 ff ff ?? ?? ?? ?? 8b 85 f0 fd ff ff 89 85 28 f4 ff ff 8b 8d 28 f4 ff ff 66 8b 11 66 89 95 26 f4 ff ff 8b 85 2c f4 ff ff 66 3b 10 75 4b 66 83 bd 26 f4 ff ff 00 74 } //1
		$a_01_1 = {41 6e 74 69 56 69 72 75 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //1 AntiVirusDisableNotify
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run\
		$a_01_3 = {2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 2e 00 5c 00 25 00 73 00 20 00 26 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 2e 00 5c 00 25 00 73 00 5c 00 56 00 6f 00 6c 00 44 00 72 00 69 00 76 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 /c start .\%s & start .\%s\VolDriver.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Phorpiex_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Phorpiex.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 09 00 00 "
		
	strings :
		$a_01_0 = {ba 05 00 00 00 66 89 55 d0 8d 45 ec 50 8d 4d a0 51 6a 00 6a 00 6a 20 6a 00 6a 00 6a 00 8b 55 08 52 6a 00 ff 15 2c 00 41 00 } //6
		$a_01_1 = {4e 65 77 52 65 6d 6f 74 65 48 6f 73 74 } //1 NewRemoteHost
		$a_01_2 = {46 69 72 65 77 61 6c 6c 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //1 FirewallDisableNotify
		$a_01_3 = {41 6e 74 69 53 70 79 77 61 72 65 4f 76 65 72 72 69 64 65 } //1 AntiSpywareOverride
		$a_01_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 57 } //1 InternetOpenUrlW
		$a_01_5 = {55 6e 6d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //1 UnmapViewOfFile
		$a_01_6 = {47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 45 78 57 } //1 GetDiskFreeSpaceExW
		$a_01_7 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 SetClipboardData
		$a_01_8 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run\
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=14
 
}