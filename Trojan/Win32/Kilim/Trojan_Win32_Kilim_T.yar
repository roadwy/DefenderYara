
rule Trojan_Win32_Kilim_T{
	meta:
		description = "Trojan:Win32/Kilim.T,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 22 68 74 74 70 3a 2f 2f 77 68 6f 73 2e 61 6d 75 6e 67 2e 75 73 2f 70 69 6e 67 6a 73 2f 3f 6b 3d [0-0f] 2c 20 22 70 69 6e 67 6a 73 2e 6a 73 22 } //3
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 63 68 72 6f 6d 65 2e 65 78 65 20 2f 46 } //3 taskkill /IM chrome.exe /F
		$a_01_2 = {25 63 69 6b 61 6e 5f 73 69 74 65 25 2f 43 69 76 61 6e 5f 43 6f 64 65 72 2f 62 61 63 6b 67 72 6f 75 6e 64 2e 6a 73 } //1 %cikan_site%/Civan_Coder/background.js
		$a_01_3 = {2f 2f 25 63 69 6b 61 6e 5f 73 69 74 65 25 2f 73 6b 79 5f 63 6f 64 65 72 2f 73 6b 79 2e 6a 73 } //1 //%cikan_site%/sky_coder/sky.js
		$a_01_4 = {77 67 65 74 2e 65 78 65 20 2d 4f 20 22 25 41 5f 41 70 70 44 61 74 61 25 5c 61 72 73 69 76 2e 65 78 65 22 20 22 25 50 68 70 5f 4c 69 6e 6b 25 61 72 73 69 76 5f 6c 69 6e 6b 22 } //1 wget.exe -O "%A_AppData%\arsiv.exe" "%Php_Link%arsiv_link"
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}