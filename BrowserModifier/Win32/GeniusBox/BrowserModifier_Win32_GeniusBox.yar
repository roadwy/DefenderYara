
rule BrowserModifier_Win32_GeniusBox{
	meta:
		description = "BrowserModifier:Win32/GeniusBox,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 6d 00 61 00 78 00 77 00 65 00 62 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 3f 00 69 00 5f 00 } //1 http://www.maxwebsearch.com/s?i_
		$a_01_1 = {47 00 65 00 6e 00 69 00 75 00 73 00 42 00 6f 00 78 00 20 00 45 00 6e 00 68 00 61 00 6e 00 63 00 65 00 64 00 20 00 53 00 65 00 61 00 72 00 63 00 68 00 } //1 GeniusBox Enhanced Search
		$a_01_2 = {43 4f 4e 46 49 47 5f 4b 45 59 5f 53 45 54 5f 48 4f 4d 45 5f 50 41 47 45 } //1 CONFIG_KEY_SET_HOME_PAGE
		$a_01_3 = {43 3a 5c 50 72 6f 6a 65 63 74 73 5c 45 78 74 65 6e 73 69 6f 6e 73 5c 42 48 4f 5c 49 6e 73 74 61 6c 6c 5c 52 65 6c 65 61 73 65 5c 67 62 5f 65 78 5f 69 6e 73 74 61 6c 6c 2e 70 64 62 } //1 C:\Projects\Extensions\BHO\Install\Release\gb_ex_install.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}