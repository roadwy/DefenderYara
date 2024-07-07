
rule BrowserModifier_Win32_SearchSetter{
	meta:
		description = "BrowserModifier:Win32/SearchSetter,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2d 73 65 61 72 63 68 69 6e 67 2e 63 6f 6d 2f 3f 70 69 64 3d 73 26 73 3d } //10 www-searching.com/?pid=s&s=
		$a_01_1 = {53 00 65 00 74 00 74 00 65 00 72 00 45 00 78 00 65 00 2e 00 65 00 78 00 65 00 } //10 SetterExe.exe
		$a_01_2 = {63 68 72 6f 6d 65 3a 2f 2f 73 65 74 74 69 6e 67 73 2d 66 72 61 6d 65 2f 23 73 79 69 35 31 38 } //1 chrome://settings-frame/#syi518
		$a_01_3 = {50 00 52 00 45 00 56 00 53 00 45 00 41 00 52 00 43 00 48 00 49 00 45 00 00 00 } //1
		$a_01_4 = {49 00 45 00 53 00 45 00 54 00 00 00 } //1
		$a_01_5 = {52 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 20 00 6f 00 6e 00 20 00 56 00 4d 00 57 00 61 00 72 00 65 00 } //1 Running on VMWare
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=14
 
}