
rule BrowserModifier_Win32_TopGuide{
	meta:
		description = "BrowserModifier:Win32/TopGuide,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 53 6d 61 72 74 54 6f 6f 6c 00 } //10
		$a_01_1 = {53 6d 61 72 74 54 6f 6f 6c 2e 64 6c 6c 00 } //10
		$a_01_2 = {2e 70 6c 75 73 74 61 62 2e 63 6f 2e 6b 72 2f 75 70 64 61 74 65 2f 00 } //1
		$a_01_3 = {73 68 6f 70 2e 63 6f 6d 2f 73 65 61 72 63 68 2f } //1 shop.com/search/
		$a_01_4 = {2f 74 6f 70 67 75 69 64 65 2e 63 6f 2e 6b 72 2f 62 61 72 2e 61 73 70 3f 6b 3d 25 73 26 69 64 3d 25 73 26 6d 3d 25 73 } //1 /topguide.co.kr/bar.asp?k=%s&id=%s&m=%s
		$a_01_5 = {53 45 41 52 43 48 5f 4b 45 59 57 4f 52 44 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=13
 
}
rule BrowserModifier_Win32_TopGuide_2{
	meta:
		description = "BrowserModifier:Win32/TopGuide,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 6f 70 47 75 69 64 65 2e 69 6e 69 00 00 00 00 68 74 74 70 3a 2f 2f 74 6f 70 67 75 69 64 65 2e 63 6f 2e 6b 72 2f 75 70 64 61 74 65 2f } //1
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 54 6f 70 47 75 69 64 65 } //1 Software\TopGuide
		$a_01_2 = {49 6e 73 74 61 6c 6c 48 6f 6f 6b 00 61 64 63 2e 64 6c 6c 00 49 6e 66 6f 54 61 62 00 54 6f 70 47 75 69 64 65 5f } //1
		$a_01_3 = {54 6f 70 47 75 69 64 65 2e 64 6c 6c 00 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}