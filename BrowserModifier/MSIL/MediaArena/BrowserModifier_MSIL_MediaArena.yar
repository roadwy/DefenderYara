
rule BrowserModifier_MSIL_MediaArena{
	meta:
		description = "BrowserModifier:MSIL/MediaArena,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_80_0 = {73 65 61 72 63 68 20 65 6e 67 69 6e 65 } //search engine  1
		$a_80_1 = {67 65 74 5f 42 72 6f 77 73 65 72 54 79 70 65 } //get_BrowserType  1
		$a_80_2 = {4f 70 74 69 6f 6e 61 6c 4f 66 66 65 72 57 69 6e 64 6f 77 } //OptionalOfferWindow  1
		$a_80_3 = {69 73 4f 70 74 69 6f 6e 61 6c 4f 66 66 65 72 53 65 6c 65 63 74 65 64 } //isOptionalOfferSelected  1
		$a_80_4 = {67 65 74 5f 53 65 61 72 63 68 45 6e 67 69 6e 65 55 72 6c } //get_SearchEngineUrl  1
		$a_80_5 = {41 64 64 53 65 61 72 63 68 45 6e 67 69 6e 65 54 6f 45 64 67 65 } //AddSearchEngineToEdge  1
		$a_80_6 = {43 68 61 6e 67 65 53 65 61 72 63 68 45 6e 67 69 6e 65 } //ChangeSearchEngine  1
		$a_80_7 = {50 44 46 43 6f 6e 76 65 72 74 2e 65 78 65 } //PDFConvert.exe  1
		$a_80_8 = {6e 6f 67 6f 73 65 61 72 63 68 2e 63 6f 6d } //nogosearch.com  1
		$a_80_9 = {77 69 73 65 77 65 62 73 65 61 72 63 68 2e 63 6f 6d } //wisewebsearch.com  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=10
 
}
rule BrowserModifier_MSIL_MediaArena_2{
	meta:
		description = "BrowserModifier:MSIL/MediaArena,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {45 64 55 70 2e 57 44 2e 65 78 65 } //EdUp.WD.exe  1
		$a_80_1 = {45 64 61 74 65 2e 65 78 65 } //Edate.exe  1
		$a_80_2 = {50 44 46 53 75 70 65 72 48 65 72 6f } //PDFSuperHero  1
		$a_80_3 = {69 6e 73 74 61 6c 6c 2e 6f 6e 6c 69 6e 65 70 64 66 2d 63 6f 6e 76 65 72 74 65 72 } //install.onlinepdf-converter  1
		$a_80_4 = {65 64 67 65 3a 2f 2f 73 65 74 74 69 6e 67 73 2f 73 65 61 72 63 68 45 6e 67 69 6e 65 73 } //edge://settings/searchEngines  1
		$a_80_5 = {64 65 66 61 75 6c 74 5f 73 65 61 72 63 68 5f 70 72 6f 76 69 64 65 72 5f 64 61 74 61 } //default_search_provider_data  1
		$a_80_6 = {64 65 66 61 75 6c 74 73 65 61 72 63 68 64 6f 6d 61 69 6e 76 61 6c 75 65 } //defaultsearchdomainvalue  1
		$a_80_7 = {45 78 63 65 70 74 69 6f 6e 20 69 6e 20 50 61 79 6c 6f 61 64 55 74 69 6c 73 2e 44 65 66 61 75 6c 74 42 72 6f 77 73 65 72 44 65 74 61 69 6c 73 28 29 3a 20 7b 31 7d } //Exception in PayloadUtils.DefaultBrowserDetails(): {1}  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}
rule BrowserModifier_MSIL_MediaArena_3{
	meta:
		description = "BrowserModifier:MSIL/MediaArena,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_80_0 = {53 69 6d 4b 73 74 6f 6b } //SimKstok  1
		$a_80_1 = {44 65 66 61 75 6c 74 20 62 72 6f 77 73 65 72 } //Default browser  1
		$a_80_2 = {65 64 67 65 3a 2f 2f 73 65 74 74 69 6e 67 73 2f 73 65 61 72 63 68 45 6e 67 69 6e 65 73 } //edge://settings/searchEngines  1
		$a_80_3 = {53 74 65 70 20 34 20 3a 20 50 61 73 74 65 20 73 65 74 74 69 6e 67 73 20 75 72 6c 20 69 6e 20 65 64 20 65 64 3a 2f 2f 73 65 74 74 69 6e 67 73 2f 73 65 61 72 63 68 45 6e 67 69 6e 65 73 } //Step 4 : Paste settings url in ed ed://settings/searchEngines  1
		$a_80_4 = {3a 7b 30 7d 3a 45 78 63 65 70 74 69 6f 6e 20 7b 31 7d } //:{0}:Exception {1}  1
		$a_80_5 = {53 74 65 70 20 34 20 3a 20 74 79 70 65 20 69 6e 20 73 65 74 74 69 6e 67 73 20 75 72 6c 20 69 6e 20 65 64 20 65 64 3a 2f 2f 73 65 74 74 69 6e 67 73 2f 73 65 61 72 63 68 45 6e 67 69 6e 65 73 } //Step 4 : type in settings url in ed ed://settings/searchEngines  1
		$a_80_6 = {53 74 65 70 20 35 20 3a 20 73 65 74 74 69 6e 67 73 20 6f 70 65 6e 65 64 } //Step 5 : settings opened  1
		$a_80_7 = {53 74 65 70 20 36 20 3a 20 6d 6f 76 65 64 20 74 6f 20 73 65 61 72 63 68 } //Step 6 : moved to search  1
		$a_80_8 = {53 74 65 70 20 37 20 3a 20 50 61 73 74 65 20 73 65 61 72 63 68 20 70 72 6f 64 75 63 74 } //Step 7 : Paste search product  1
		$a_80_9 = {53 74 65 70 20 37 20 3a 20 74 79 70 65 20 69 6e 20 73 65 61 72 63 68 20 70 72 6f 64 75 63 74 } //Step 7 : type in search product  1
		$a_80_10 = {53 74 65 70 20 38 20 3a 20 63 68 61 6e 67 65 64 20 74 68 65 20 73 65 61 72 63 68 20 65 6e 67 69 6e 65 } //Step 8 : changed the search engine  1
		$a_80_11 = {53 74 65 70 20 39 20 3a 20 47 72 61 63 65 66 75 6c 6c 79 20 63 6c 6f 73 65 64 20 65 64 67 65 } //Step 9 : Gracefully closed edge  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1) >=12
 
}
rule BrowserModifier_MSIL_MediaArena_4{
	meta:
		description = "BrowserModifier:MSIL/MediaArena,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {63 00 6f 00 6d 00 2f 00 6e 00 61 00 76 00 3f 00 73 00 74 00 72 00 69 00 6e 00 67 00 5f 00 69 00 6e 00 74 00 65 00 72 00 70 00 6f 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 3d 00 47 00 45 00 54 00 5f 00 4f 00 53 00 4f 00 55 00 26 00 61 00 70 00 70 00 49 00 64 00 3d 00 } //3 com/nav?string_interpolation=GET_OSOU&appId=
		$a_01_1 = {77 00 65 00 20 00 77 00 69 00 6c 00 6c 00 20 00 75 00 70 00 64 00 61 00 74 00 65 00 20 00 69 00 73 00 5f 00 73 00 70 00 5f 00 73 00 65 00 74 00 20 00 3d 00 20 00 74 00 72 00 75 00 65 00 20 00 21 00 21 00 } //3 we will update is_sp_set = true !!
		$a_01_2 = {74 00 6f 00 20 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 20 00 42 00 69 00 6e 00 67 00 20 00 70 00 6f 00 70 00 75 00 70 00 20 00 2e 00 2e 00 2e 00 } //3 to disable Bing popup ...
		$a_01_3 = {53 00 4f 00 5f 00 64 00 65 00 63 00 6c 00 69 00 6e 00 65 00 64 00 } //3 SO_declined
		$a_01_4 = {45 00 61 00 74 00 69 00 6e 00 67 00 20 00 6b 00 65 00 79 00 20 00 73 00 74 00 72 00 6f 00 6b 00 65 00 } //2 Eating key stroke
		$a_01_5 = {47 00 45 00 54 00 5f 00 49 00 53 00 5f 00 4d 00 4f 00 4e 00 45 00 54 00 49 00 5a 00 45 00 } //1 GET_IS_MONETIZE
		$a_01_6 = {74 00 68 00 61 00 6e 00 6b 00 79 00 6f 00 75 00 3f 00 74 00 79 00 69 00 64 00 3d 00 } //1 thankyou?tyid=
		$a_01_7 = {54 00 59 00 50 00 5f 00 6f 00 70 00 65 00 6e 00 65 00 64 00 } //1 TYP_opened
		$a_01_8 = {64 00 65 00 66 00 61 00 75 00 6c 00 74 00 20 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 20 00 63 00 68 00 61 00 6e 00 67 00 65 00 20 00 69 00 73 00 20 00 73 00 65 00 6e 00 74 00 20 00 74 00 6f 00 20 00 6d 00 6f 00 6e 00 65 00 74 00 69 00 7a 00 } //1 default browser change is sent to monetiz
		$a_01_9 = {47 00 65 00 74 00 45 00 64 00 67 00 65 00 50 00 72 00 6f 00 63 00 57 00 69 00 6e 00 64 00 6f 00 77 00 20 00 2d 00 2d 00 20 00 4d 00 73 00 45 00 64 00 67 00 65 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1 GetEdgeProcWindow -- MsEdge process
		$a_01_10 = {72 00 65 00 61 00 64 00 69 00 6e 00 67 00 20 00 27 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 5f 00 73 00 65 00 61 00 72 00 63 00 68 00 5f 00 70 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00 5f 00 64 00 61 00 74 00 61 00 27 00 20 00 66 00 61 00 69 00 6c 00 75 00 72 00 65 00 } //1 reading 'default_search_provider_data' failure
		$a_01_11 = {61 00 64 00 76 00 65 00 72 00 74 00 69 00 73 00 65 00 6d 00 65 00 6e 00 74 00 73 00 20 00 62 00 61 00 73 00 65 00 64 00 20 00 6f 00 6e 00 20 00 79 00 6f 00 75 00 72 00 20 00 73 00 65 00 61 00 72 00 63 00 68 00 65 00 73 00 } //1 advertisements based on your searches
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}