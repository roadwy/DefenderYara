
rule Trojan_Win32_Kilim_U{
	meta:
		description = "Trojan:Win32/Kilim.U,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 63 68 74 61 73 6b 73 20 2f 44 65 6c 65 74 65 20 2f 54 4e 20 47 6f 6f 67 6c 65 55 70 64 61 74 65 54 61 73 6b 4d 61 63 68 69 6e 65 43 6f 72 65 20 2f 46 } //1 schtasks /Delete /TN GoogleUpdateTaskMachineCore /F
		$a_01_1 = {73 63 68 74 61 73 6b 73 20 2f 44 65 6c 65 74 65 20 2f 54 4e 20 47 6f 6f 67 6c 65 55 70 64 61 74 65 54 61 73 6b 4d 61 63 68 69 6e 65 55 41 20 2f 46 } //1 schtasks /Delete /TN GoogleUpdateTaskMachineUA /F
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 63 68 72 6f 6d 65 2e 65 78 65 20 2f 46 } //1 taskkill /IM chrome.exe /F
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 62 72 6f 77 73 65 72 2e 65 78 65 20 2f 46 } //1 taskkill /IM browser.exe /F
		$a_01_4 = {77 67 65 74 2e 65 78 65 20 2d 4f 20 22 25 41 5f 41 70 70 44 61 74 61 25 5c 61 72 73 69 76 2e 65 78 65 22 20 22 25 50 68 70 5f 4c 69 6e 6b 25 61 72 73 69 76 5f 6c 69 6e 6b 22 } //1 wget.exe -O "%A_AppData%\arsiv.exe" "%Php_Link%arsiv_link"
		$a_01_5 = {26 00 57 00 69 00 6e 00 64 00 6f 00 77 00 20 00 53 00 70 00 79 00 } //1 &Window Spy
		$a_01_6 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 50 68 70 5f 4c 69 6e 6b 20 2e 20 22 6a 73 22 2c 20 22 } //1 GetDownload(Php_Link . "js", "
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}