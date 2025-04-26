
rule BrowserModifier_Win32_Istbar_D{
	meta:
		description = "BrowserModifier:Win32/Istbar.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {7b 38 43 42 41 31 42 34 39 2d 38 31 34 34 2d 34 37 32 31 2d 41 37 42 31 2d 36 34 43 35 37 38 43 39 45 45 44 37 7d } //{8CBA1B49-8144-4721-A7B1-64C578C9EED7}  1
		$a_80_1 = {53 69 64 65 46 69 6e 64 00 } //SideFind  1
		$a_01_2 = {73 68 6f 70 70 69 6e 67 61 75 74 6f 73 65 61 72 63 68 } //1 shoppingautosearch
		$a_01_3 = {77 65 62 61 75 74 6f 73 65 61 72 63 68 } //1 webautosearch
		$a_01_4 = {53 65 61 72 63 68 53 69 74 65 00 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule BrowserModifier_Win32_Istbar_D_2{
	meta:
		description = "BrowserModifier:Win32/Istbar.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 69 64 65 46 69 6e 64 } //1 SOFTWARE\Microsoft\SideFind
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 45 78 70 6c 6f 72 65 72 20 42 61 72 73 5c 7b 38 43 42 41 31 42 34 39 2d 38 31 34 34 2d 34 37 32 31 2d 41 37 42 31 2d 36 34 43 35 37 38 43 39 45 45 44 37 7d } //1 Software\Microsoft\Internet Explorer\Explorer Bars\{8CBA1B49-8144-4721-A7B1-64C578C9EED7}
		$a_01_2 = {53 65 61 72 63 68 53 69 74 65 } //1 SearchSite
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 53 69 64 65 46 69 6e 64 5c 48 69 73 74 6f 72 79 } //1 SOFTWARE\SideFind\History
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule BrowserModifier_Win32_Istbar_D_3{
	meta:
		description = "BrowserModifier:Win32/Istbar.D,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {62 61 6e 64 2e 64 6c 6c } //1 band.dll
		$a_01_1 = {30 30 30 32 31 34 39 34 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 } //1 00021494-0000-0000-C000-000000000046
		$a_01_2 = {43 37 39 39 34 45 33 30 2d 33 34 32 37 2d 34 37 35 62 2d 39 45 36 41 2d 38 35 34 30 31 36 38 37 30 43 44 36 } //1 C7994E30-3427-475b-9E6A-854016870CD6
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 68 79 63 67 5c 68 79 63 67 } //1 Software\hycg\hycg
		$a_01_4 = {68 79 63 67 5f 4d 61 69 6e } //1 hycg_Main
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 44 69 73 63 61 72 64 61 62 6c 65 5c 50 6f 73 74 53 65 74 75 70 5c 43 6f 6d 70 6f 6e 65 6e 74 20 43 61 74 65 67 6f 72 69 65 73 5c } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Discardable\PostSetup\Component Categories\
		$a_01_6 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //1 GetWindowsDirectoryA
		$a_01_7 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}