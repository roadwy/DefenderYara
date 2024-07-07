
rule BrowserModifier_Win32_OneStepSearch_B{
	meta:
		description = "BrowserModifier:Win32/OneStepSearch.B,SIGNATURE_TYPE_PEHSTR,19 00 19 00 07 00 00 "
		
	strings :
		$a_01_0 = {7b 31 46 42 41 30 34 45 45 2d 33 30 32 34 2d 31 31 44 32 2d 38 46 31 46 2d 30 30 30 30 46 38 37 41 42 44 31 36 7d } //10 {1FBA04EE-3024-11D2-8F1F-0000F87ABD16}
		$a_01_1 = {61 75 63 74 69 6f 6e 00 61 75 6b 74 69 6f 6e 00 62 6f 6f 6b 00 62 6f 75 74 69 71 75 65 00 63 61 6c 6c 00 63 68 61 74 } //10
		$a_01_2 = {50 61 74 68 3d 50 72 6f 66 69 6c 65 73 2f 66 6f 6f } //1 Path=Profiles/foo
		$a_01_3 = {3f 70 72 74 3d 25 73 26 6b 65 79 77 6f 72 64 73 3d 7b 73 65 61 72 63 68 54 65 72 6d 73 7d } //1 ?prt=%s&keywords={searchTerms}
		$a_01_4 = {63 68 72 6f 6d 65 5c 63 68 72 6f 6d 65 2e 72 64 66 } //1 chrome\chrome.rdf
		$a_01_5 = {53 68 6f 77 54 6f 6f 6c 62 61 72 42 75 74 74 6f 6e } //1 ShowToolbarButton
		$a_01_6 = {43 6f 6d 6d 61 6e 64 00 49 6e 73 74 61 6c 6c 00 4d 61 69 6e 00 53 65 72 76 69 63 65 } //1 潃浭湡d湉瑳污l慍湩匀牥楶散
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=25
 
}
rule BrowserModifier_Win32_OneStepSearch_B_2{
	meta:
		description = "BrowserModifier:Win32/OneStepSearch.B,SIGNATURE_TYPE_PEHSTR,20 00 20 00 08 00 00 "
		
	strings :
		$a_01_0 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 65 61 72 63 68 53 63 6f 70 65 73 } //10 \Internet Explorer\SearchScopes
		$a_01_1 = {7b 31 46 42 41 30 34 45 45 2d 33 30 32 34 2d 31 31 44 32 2d 38 46 31 46 2d 30 30 30 30 46 38 37 41 42 44 31 36 7d } //10 {1FBA04EE-3024-11D2-8F1F-0000F87ABD16}
		$a_01_2 = {61 75 63 74 69 6f 6e 00 61 75 6b 74 69 6f 6e 00 62 6f 6f 6b 00 62 6f 75 74 69 71 75 65 00 63 61 6c 6c 00 63 68 61 74 } //10
		$a_01_3 = {50 61 74 68 3d 50 72 6f 66 69 6c 65 73 2f 66 6f 6f } //1 Path=Profiles/foo
		$a_01_4 = {3f 70 72 74 3d 25 73 26 6b 65 79 77 6f 72 64 73 3d 7b 73 65 61 72 63 68 54 65 72 6d 73 7d } //1 ?prt=%s&keywords={searchTerms}
		$a_01_5 = {63 68 72 6f 6d 65 5c 63 68 72 6f 6d 65 2e 72 64 66 } //1 chrome\chrome.rdf
		$a_01_6 = {53 68 6f 77 54 6f 6f 6c 62 61 72 42 75 74 74 6f 6e } //1 ShowToolbarButton
		$a_01_7 = {43 6f 6d 6d 61 6e 64 00 49 6e 73 74 61 6c 6c 00 4d 61 69 6e 00 53 65 72 76 69 63 65 } //1 潃浭湡d湉瑳污l慍湩匀牥楶散
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=32
 
}