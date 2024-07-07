
rule BrowserModifier_MSIL_MediaArena_MTB{
	meta:
		description = "BrowserModifier:MSIL/MediaArena!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {67 65 74 5f 53 68 6f 77 } //get_Show  1
		$a_80_1 = {4f 70 74 69 6f 6e 61 6c 4f 66 66 65 72 } //OptionalOffer  1
		$a_80_2 = {49 6e 73 74 61 6c 6c 46 72 65 65 50 44 46 } //InstallFreePDF  1
		$a_80_3 = {67 65 74 5f 42 72 6f 77 73 65 72 54 79 70 65 } //get_BrowserType  1
		$a_80_4 = {44 65 66 61 75 6c 74 53 65 61 72 63 68 45 6e 67 69 6e 65 } //DefaultSearchEngine  1
		$a_80_5 = {46 72 65 65 50 44 46 50 6c 75 73 49 6e 73 74 } //FreePDFPlusInst  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule BrowserModifier_MSIL_MediaArena_MTB_2{
	meta:
		description = "BrowserModifier:MSIL/MediaArena!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {73 65 61 72 63 68 45 6e 67 69 6e 65 } //searchEngine  1
		$a_80_1 = {73 65 61 72 63 68 20 6f 66 66 65 72 } //search offer  1
		$a_80_2 = {44 65 66 61 75 6c 74 20 62 72 6f 77 73 65 72 } //Default browser  1
		$a_80_3 = {53 65 61 72 63 68 76 69 62 65 73 6e 6f 77 } //Searchvibesnow  1
		$a_80_4 = {50 44 46 53 75 70 65 72 48 65 72 6f 2e 65 78 65 } //PDFSuperHero.exe  1
		$a_80_5 = {65 64 67 65 3a 2f 2f 73 65 74 74 69 6e 67 73 2f 73 65 61 72 63 68 45 6e 67 69 6e 65 73 } //edge://settings/searchEngines  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule BrowserModifier_MSIL_MediaArena_MTB_3{
	meta:
		description = "BrowserModifier:MSIL/MediaArena!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {4f 66 66 65 72 53 63 72 65 65 6e } //OfferScreen  1
		$a_80_1 = {6f 66 66 65 72 57 69 6e 64 6f 77 } //offerWindow  1
		$a_80_2 = {6f 66 66 65 72 73 63 72 65 65 6e 2e 78 61 6d 6c } //offerscreen.xaml  1
		$a_80_3 = {44 65 66 42 72 6f 77 73 65 72 } //DefBrowser  1
		$a_80_4 = {42 72 6f 77 73 65 72 44 6f 6e 65 4c 6f 61 64 65 64 57 69 74 68 55 72 6c } //BrowserDoneLoadedWithUrl  1
		$a_80_5 = {64 65 66 61 75 6c 74 5f 73 65 61 72 63 68 5f 70 72 6f 76 69 64 65 72 5f 64 61 74 61 } //default_search_provider_data  1
		$a_80_6 = {67 65 74 5f 41 70 70 53 65 74 74 69 6e 67 73 } //get_AppSettings  1
		$a_80_7 = {43 68 61 6e 67 65 53 72 68 63 42 6f 78 } //ChangeSrhcBox  1
		$a_80_8 = {50 44 46 20 43 65 6e 74 72 61 6c } //PDF Central  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=9
 
}
rule BrowserModifier_MSIL_MediaArena_MTB_4{
	meta:
		description = "BrowserModifier:MSIL/MediaArena!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {4f 66 66 65 72 53 63 72 65 65 6e } //OfferScreen  1
		$a_80_1 = {6f 66 66 65 72 57 69 6e 64 6f 77 } //offerWindow  1
		$a_80_2 = {49 44 53 5f 44 45 46 41 55 4c 54 5f 42 52 4f 57 53 45 52 } //IDS_DEFAULT_BROWSER  1
		$a_80_3 = {49 44 53 5f 44 45 46 41 55 4c 54 5f 53 45 41 52 43 48 5f 50 52 4f 56 49 44 45 52 5f 44 41 54 41 } //IDS_DEFAULT_SEARCH_PROVIDER_DATA  1
		$a_80_4 = {49 44 53 5f 49 53 5f 49 4e 53 54 41 4c 4c 5f 41 43 43 45 50 54 45 44 } //IDS_IS_INSTALL_ACCEPTED  1
		$a_80_5 = {62 72 6f 77 73 65 72 5f 6c 6f 61 64 69 6e 67 5f 74 69 6d 65 5f 75 72 6c } //browser_loading_time_url  1
		$a_80_6 = {67 65 74 5f 41 70 70 53 65 74 74 69 6e 67 73 } //get_AppSettings  1
		$a_80_7 = {63 68 61 6e 67 65 20 73 65 61 72 63 68 20 73 65 74 74 69 6e 67 73 } //change search settings  1
		$a_80_8 = {50 64 66 4d 61 6e 61 67 65 72 } //PdfManager  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=9
 
}
rule BrowserModifier_MSIL_MediaArena_MTB_5{
	meta:
		description = "BrowserModifier:MSIL/MediaArena!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 "
		
	strings :
		$a_80_0 = {4f 66 66 65 72 53 63 72 65 65 6e } //OfferScreen  1
		$a_80_1 = {6f 66 66 65 72 57 69 6e 64 6f 77 } //offerWindow  1
		$a_80_2 = {44 65 66 42 72 6f 77 73 65 72 } //DefBrowser  1
		$a_80_3 = {49 44 53 5f 44 4f 57 4e 4c 4f 41 44 5f 42 52 4f 57 53 45 52 } //IDS_DOWNLOAD_BROWSER  1
		$a_80_4 = {49 44 53 5f 44 45 46 41 55 4c 54 5f 42 52 4f 57 53 45 52 } //IDS_DEFAULT_BROWSER  1
		$a_80_5 = {49 44 53 5f 45 44 47 45 5f 53 45 54 54 49 4e 47 53 5f 44 45 46 5f 42 52 4f 57 53 45 52 } //IDS_EDGE_SETTINGS_DEF_BROWSER  1
		$a_80_6 = {42 72 6f 77 73 65 72 4c 6f 61 64 65 64 57 69 74 68 55 72 6c } //BrowserLoadedWithUrl  1
		$a_80_7 = {43 4f 4c 4c 45 43 54 5f 44 41 54 41 5f 53 45 41 52 43 48 5f 45 4e 47 49 4e 45 } //COLLECT_DATA_SEARCH_ENGINE  1
		$a_80_8 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_9 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*-100+(#a_80_9  & 1)*-100) >=8
 
}