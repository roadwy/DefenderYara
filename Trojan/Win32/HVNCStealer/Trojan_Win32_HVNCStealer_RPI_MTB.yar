
rule Trojan_Win32_HVNCStealer_RPI_MTB{
	meta:
		description = "Trojan:Win32/HVNCStealer.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {41 56 45 5f 4d 41 52 49 41 } //1 AVE_MARIA
		$a_01_1 = {34 35 2e 31 32 2e 32 31 32 2e 31 31 30 } //1 45.12.212.110
		$a_01_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 73 68 65 6c 6c 33 32 2e 64 6c 6c 2c 23 36 31 } //1 rundll32.exe shell32.dll,#61
		$a_01_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 } //1 cmd.exe /c start 
		$a_01_4 = {63 68 72 6f 6d 65 2e 65 78 65 } //1 chrome.exe
		$a_01_5 = {70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //1 profiles.ini
		$a_01_6 = {66 69 72 65 66 6f 78 2e 65 78 65 } //1 firefox.exe
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
		$a_01_8 = {53 6c 65 65 70 } //1 Sleep
		$a_01_9 = {47 65 74 54 6f 70 57 69 6e 64 6f 77 } //1 GetTopWindow
		$a_01_10 = {2d 2d 6e 6f 2d 73 61 6e 64 62 6f 78 20 2d 2d 61 6c 6c 6f 77 2d 6e 6f 2d 73 61 6e 64 62 6f 78 2d 6a 6f 62 } //1 --no-sandbox --allow-no-sandbox-job
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}