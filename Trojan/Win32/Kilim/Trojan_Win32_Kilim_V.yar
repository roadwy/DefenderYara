
rule Trojan_Win32_Kilim_V{
	meta:
		description = "Trojan:Win32/Kilim.V,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 53 69 74 65 5f 4c 69 6e 6b 2c 20 50 61 74 68 2c 20 32 34 30 2c 20 35 30 30 29 } //2 GetDownload(Site_Link, Path, 240, 500)
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 63 68 72 6f 6d 65 2e 65 78 65 20 2f 46 } //2 taskkill /IM chrome.exe /F
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 62 72 6f 77 73 65 72 2e 65 78 65 20 2f 46 } //2 taskkill /IM browser.exe /F
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 6f 70 65 72 61 2e 65 78 65 20 2f 46 } //2 taskkill /IM opera.exe /F
		$a_01_4 = {25 63 69 6b 61 6e 5f 73 69 74 65 25 2f 43 69 76 61 6e 5f 43 6f 64 65 72 2f 62 61 63 6b 67 72 6f 75 6e 64 2e 6a 73 } //1 %cikan_site%/Civan_Coder/background.js
		$a_03_5 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 22 68 74 74 70 3a 2f 2f 77 68 6f 73 2e 61 6d 75 6e 67 2e 75 73 2f 70 69 6e 67 6a 73 2f 3f 6b 3d [0-0f] 2c 20 22 70 69 6e 67 6a 73 2e 6a 73 22 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=9
 
}