
rule Trojan_BAT_Kilim_A{
	meta:
		description = "Trojan:BAT/Kilim.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_00_0 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //1 Form1_Load
		$a_00_1 = {4d 79 50 72 6f 6a 65 63 74 } //1 MyProject
		$a_00_2 = {5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 73 00 } //1 \Google\Chrome\User Data\Default\Preferences
		$a_00_3 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 46 00 20 00 2f 00 49 00 4d 00 20 00 63 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00 } //1 taskkill /F /IM chrome.exe
		$a_00_4 = {2f 00 62 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 2e 00 6a 00 73 00 } //1 /background.js
		$a_00_5 = {2f 00 6d 00 61 00 6e 00 69 00 66 00 65 00 73 00 74 00 2e 00 6a 00 73 00 6f 00 6e 00 } //1 /manifest.json
		$a_00_6 = {2f 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 73 00 2e 00 65 00 78 00 65 00 } //1 /Preferences.exe
		$a_03_7 = {01 00 70 28 ?? 00 00 0a 0a 7e ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a 72 ?? ?? 00 70 72 ?? ?? 00 70 6f ?? 00 00 0a } //2
		$a_03_8 = {70 18 16 15 28 ?? 00 00 0a 26 06 72 ?? ?? 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_03_7  & 1)*2+(#a_03_8  & 1)*2) >=7
 
}