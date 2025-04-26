
rule BrowserModifier_Win32_MediaArena{
	meta:
		description = "BrowserModifier:Win32/MediaArena,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {67 65 74 5f 54 68 61 6e 6b 79 6f 75 50 61 67 65 55 72 6c } //get_ThankyouPageUrl  1
		$a_80_1 = {67 65 74 5f 55 6e 69 6e 73 74 61 6c 6c 53 65 61 72 63 68 55 72 6c } //get_UninstallSearchUrl  1
		$a_80_2 = {67 65 74 5f 53 74 61 74 73 55 72 6c } //get_StatsUrl  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}
rule BrowserModifier_Win32_MediaArena_2{
	meta:
		description = "BrowserModifier:Win32/MediaArena,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {4f 66 66 65 72 53 63 72 65 65 6e } //OfferScreen  1
		$a_80_1 = {49 44 53 5f 44 45 46 41 55 4c 54 5f 53 45 41 52 43 48 5f 50 52 4f 56 49 44 45 52 5f 44 41 54 41 } //IDS_DEFAULT_SEARCH_PROVIDER_DATA  1
		$a_80_2 = {49 44 53 5f 53 45 41 52 43 48 5f 42 4f 58 5f 4f 50 54 49 4f 4e } //IDS_SEARCH_BOX_OPTION  1
		$a_80_3 = {6f 66 66 65 72 57 69 6e 64 6f 77 } //offerWindow  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}