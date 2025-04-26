
rule Trojan_Win32_Kilim_W{
	meta:
		description = "Trojan:Win32/Kilim.W,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 63 68 74 61 73 6b 73 20 2f 44 65 6c 65 74 65 20 2f 54 4e 20 47 6f 6f 67 6c 65 55 70 64 61 74 65 54 61 73 6b 4d 61 63 68 69 6e 65 43 6f 72 65 20 2f 46 } //1 schtasks /Delete /TN GoogleUpdateTaskMachineCore /F
		$a_01_1 = {73 63 68 74 61 73 6b 73 20 2f 44 65 6c 65 74 65 20 2f 54 4e 20 47 6f 6f 67 6c 65 55 70 64 61 74 65 54 61 73 6b 4d 61 63 68 69 6e 65 55 41 20 2f 46 } //1 schtasks /Delete /TN GoogleUpdateTaskMachineUA /F
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 63 68 72 6f 6d 65 2e 65 78 65 20 2f 46 } //1 taskkill /IM chrome.exe /F
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 62 72 6f 77 73 65 72 2e 65 78 65 20 2f 46 } //1 taskkill /IM browser.exe /F
		$a_01_4 = {73 6b 79 5f 63 6f 64 65 72 5f 77 69 6e 5f 65 78 65 } //1 sky_coder_win_exe
		$a_03_5 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 22 68 74 74 70 3a 2f 2f [0-10] 2f 79 65 6e 69 2e 65 78 65 22 2c 20 22 79 65 6e 69 2e 65 78 65 22 2c 20 31 2c 20 31 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}