
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
rule BrowserModifier_Win32_MediaArena_3{
	meta:
		description = "BrowserModifier:Win32/MediaArena,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_80_0 = {43 72 61 63 6b 55 72 6c } //CrackUrl  1
		$a_80_1 = {41 63 63 65 70 74 } //Accept  1
		$a_80_2 = {44 65 63 6c 69 6e 65 } //Decline  1
		$a_80_3 = {54 68 69 73 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 69 73 20 70 6f 77 65 72 65 64 20 62 79 20 73 65 61 72 63 68 } //This application is powered by search  1
		$a_80_4 = {44 65 66 61 75 6c 74 20 42 72 6f 77 73 65 72 20 69 73 3a 20 } //Default Browser is:   1
		$a_80_5 = {73 65 61 72 63 68 } //search  1
		$a_80_6 = {50 44 46 48 75 62 } //PDFHub  1
		$a_80_7 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_8 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*-100+(#a_80_8  & 1)*-100) >=7
 
}