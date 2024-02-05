
rule BrowserModifier_MSIL_MediaArena_MTB{
	meta:
		description = "BrowserModifier:MSIL/MediaArena!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 01 00 "
		
	strings :
		$a_80_0 = {4f 66 66 65 72 53 63 72 65 65 6e } //OfferScreen  01 00 
		$a_80_1 = {6f 66 66 65 72 57 69 6e 64 6f 77 } //offerWindow  01 00 
		$a_80_2 = {44 65 66 42 72 6f 77 73 65 72 } //DefBrowser  01 00 
		$a_80_3 = {49 44 53 5f 44 4f 57 4e 4c 4f 41 44 5f 42 52 4f 57 53 45 52 } //IDS_DOWNLOAD_BROWSER  01 00 
		$a_80_4 = {49 44 53 5f 44 45 46 41 55 4c 54 5f 42 52 4f 57 53 45 52 } //IDS_DEFAULT_BROWSER  01 00 
		$a_80_5 = {49 44 53 5f 45 44 47 45 5f 53 45 54 54 49 4e 47 53 5f 44 45 46 5f 42 52 4f 57 53 45 52 } //IDS_EDGE_SETTINGS_DEF_BROWSER  01 00 
		$a_80_6 = {42 72 6f 77 73 65 72 4c 6f 61 64 65 64 57 69 74 68 55 72 6c } //BrowserLoadedWithUrl  01 00 
		$a_80_7 = {43 4f 4c 4c 45 43 54 5f 44 41 54 41 5f 53 45 41 52 43 48 5f 45 4e 47 49 4e 45 } //COLLECT_DATA_SEARCH_ENGINE  9c ff 
		$a_80_8 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  9c ff 
		$a_80_9 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  00 00 
	condition:
		any of ($a_*)
 
}