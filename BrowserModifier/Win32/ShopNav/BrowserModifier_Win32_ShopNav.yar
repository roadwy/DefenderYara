
rule BrowserModifier_Win32_ShopNav{
	meta:
		description = "BrowserModifier:Win32/ShopNav,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0b 00 00 "
		
	strings :
		$a_01_0 = {73 72 6e 67 2f 73 76 63 64 6e 6c 64 2e 70 68 70 } //2 srng/svcdnld.php
		$a_01_1 = {49 6e 20 44 6f 77 6e 6c 6f 61 64 4e 65 77 45 78 65 63 28 29 3a 20 43 6f 75 6c 64 20 6e 6f 74 20 67 65 74 20 49 6e 74 65 72 6e 65 74 20 73 65 73 73 69 6f 6e 20 68 61 6e 64 6c 65 2e } //2 In DownloadNewExec(): Could not get Internet session handle.
		$a_01_2 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 53 72 6e 67 } //3 \Program Files\Srng
		$a_01_3 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 } //2 Program Files
		$a_01_4 = {73 72 6e 67 2f 6c 6f 67 66 2e 70 68 70 } //1 srng/logf.php
		$a_01_5 = {73 72 6e 67 2f 6a 72 6e 6c 2e 70 68 70 } //1 srng/jrnl.php
		$a_01_6 = {73 72 6e 67 2f 64 6e 6c 64 2e 70 68 70 } //1 srng/dnld.php
		$a_01_7 = {73 72 6e 67 2f 72 65 67 2e 70 68 70 } //1 srng/reg.php
		$a_01_8 = {53 72 6e 67 56 65 72 } //2 SrngVer
		$a_01_9 = {53 6f 66 74 77 61 72 65 5c 53 72 6e 67 } //2 Software\Srng
		$a_01_10 = {53 72 6e 67 49 6e 69 74 2e 65 78 65 } //3 SrngInit.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*3) >=17
 
}
rule BrowserModifier_Win32_ShopNav_2{
	meta:
		description = "BrowserModifier:Win32/ShopNav,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 0b 00 00 "
		
	strings :
		$a_01_0 = {7c 66 61 69 6c 65 64 20 74 6f 20 72 65 67 69 73 74 65 72 20 75 6e 69 6e 73 74 61 6c 6c 65 72 7c } //1 |failed to register uninstaller|
		$a_01_1 = {7c 20 64 69 64 6e 27 74 20 61 63 63 65 70 74 20 7c } //1 | didn't accept |
		$a_01_2 = {7c 20 66 61 69 6c 65 64 20 73 74 6f 72 65 20 65 75 6c 61 20 7c } //1 | failed store eula |
		$a_01_3 = {7c 20 66 61 69 6c 65 64 20 74 6f 20 72 65 61 64 20 65 75 6c 61 20 7c } //1 | failed to read eula |
		$a_01_4 = {7c 20 66 61 69 6c 65 64 20 74 6f 20 61 6c 6c 6f 63 61 74 65 20 65 75 6c 61 20 7c } //1 | failed to allocate eula |
		$a_01_5 = {44 6f 20 79 6f 75 20 61 63 63 65 70 74 20 74 68 65 20 74 65 72 6d 73 20 6f 66 20 74 68 69 73 20 41 67 72 65 65 6d 65 6e 74 3f } //1 Do you accept the terms of this Agreement?
		$a_01_6 = {49 20 68 61 76 65 20 72 65 61 64 20 74 68 65 20 45 6e 64 2d 55 73 65 72 20 4c 69 63 65 6e 73 65 20 41 67 72 65 65 6d 65 6e 74 } //1 I have read the End-User License Agreement
		$a_01_7 = {46 61 69 6c 65 64 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 20 69 6e 73 74 72 75 63 74 69 6f 6e 73 20 3a 3a 20 75 72 6c 3d 25 73 20 3a 3a 20 57 69 6e 4d 61 69 6e 20 3a 3a 20 } //1 Failed to download instructions :: url=%s :: WinMain :: 
		$a_01_8 = {68 74 74 70 3a 2f 2f 25 73 2f 75 6e 69 6e 73 74 32 2e 63 67 69 3f 61 66 66 69 64 3d 25 73 26 76 65 72 3d 25 73 26 69 69 64 3d 25 73 26 67 72 70 3d 25 73 } //5 http://%s/uninst2.cgi?affid=%s&ver=%s&iid=%s&grp=%s
		$a_01_9 = {73 79 73 75 70 64 61 74 65 2e 73 68 6f 70 6e 61 76 2e 63 6f 6d } //8 sysupdate.shopnav.com
		$a_01_10 = {61 70 70 73 2e 77 65 62 73 65 72 76 69 63 65 68 6f 73 74 73 2e 63 6f 6d 00 00 00 00 62 6c 6f 67 2e 70 68 70 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*5+(#a_01_9  & 1)*8+(#a_01_10  & 1)*5) >=16
 
}