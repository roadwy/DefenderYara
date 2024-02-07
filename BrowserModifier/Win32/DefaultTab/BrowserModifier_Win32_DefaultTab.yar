
rule BrowserModifier_Win32_DefaultTab{
	meta:
		description = "BrowserModifier:Win32/DefaultTab,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 66 61 75 6c 74 54 61 62 53 65 61 72 63 68 } //01 00  DefaultTabSearch
		$a_01_1 = {61 70 69 2e 64 65 66 61 75 6c 74 74 61 62 2e 63 6f 6d 2f 74 6f 6f 6c 62 61 72 2f 6f 70 65 6e } //01 00  api.defaulttab.com/toolbar/open
		$a_03_2 = {53 6f 66 74 77 61 72 65 5c 44 65 66 61 75 6c 74 20 54 61 62 5c 50 90 02 06 61 66 66 69 64 00 00 00 75 69 64 90 00 } //01 00 
		$a_01_3 = {73 65 74 5f 68 6f 6d 65 5f 70 61 67 65 5f 6f 6e 5f 75 70 64 61 74 65 } //00 00  set_home_page_on_update
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_DefaultTab_2{
	meta:
		description = "BrowserModifier:Win32/DefaultTab,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 70 44 65 66 61 75 6c 74 54 61 62 53 65 61 72 63 68 2e 64 6c 6c } //01 00  npDefaultTabSearch.dll
		$a_01_1 = {52 65 6c 65 61 73 65 6e 70 44 65 66 61 75 6c 74 54 61 62 53 65 61 72 63 68 2e 70 64 62 } //01 00  ReleasenpDefaultTabSearch.pdb
		$a_01_2 = {44 65 66 61 75 6c 74 54 61 62 5c 75 69 64 } //01 00  DefaultTab\uid
		$a_01_3 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5f 00 54 00 61 00 62 00 5f 00 53 00 65 00 61 00 72 00 63 00 68 00 5f 00 52 00 65 00 73 00 75 00 6c 00 74 00 73 00 5f 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 52 00 65 00 61 00 64 00 79 00 } //00 00  Global\Default_Tab_Search_Results_ServiceReady
	condition:
		any of ($a_*)
 
}