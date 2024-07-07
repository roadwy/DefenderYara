
rule BrowserModifier_Win32_GonnaSearch{
	meta:
		description = "BrowserModifier:Win32/GonnaSearch,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 53 65 61 72 63 68 41 64 64 6f 6e } //1 Software\SearchAddon
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 62 6c 61 7a 65 68 69 74 73 2e 6e 65 74 2f 70 6f 70 75 70 2e } //1 http://www.blazehits.net/popup.
		$a_01_2 = {53 65 61 72 63 68 41 64 64 6f 6e 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1
		$a_01_3 = {2e 73 70 72 69 6e 6b 73 2e 63 6f 6d } //1 .sprinks.com
		$a_01_4 = {77 77 77 2e 79 61 6e 64 65 78 2e 72 75 2f 79 61 6e 64 73 65 61 72 63 68 } //1 www.yandex.ru/yandsearch
		$a_01_5 = {2e 66 69 6e 64 77 68 61 74 2e 00 00 4b 65 79 77 6f 72 64 73 3d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}