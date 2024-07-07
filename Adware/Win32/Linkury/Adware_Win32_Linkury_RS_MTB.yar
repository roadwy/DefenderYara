
rule Adware_Win32_Linkury_RS_MTB{
	meta:
		description = "Adware:Win32/Linkury.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_80_0 = {4c 69 6e 6b 75 72 79 2e 52 65 73 6f 75 72 63 65 73 2e 43 68 72 6f 6d 65 4e 65 77 54 61 62 2e 42 6c 61 63 6b 4c 69 73 74 4d 61 6e 61 67 65 72 3a 3a 42 6c 61 63 6b 4c 69 73 74 4d 61 6e 61 67 65 72 3a 54 72 75 65 3a } //Linkury.Resources.ChromeNewTab.BlackListManager::BlackListManager:True:  1
	condition:
		((#a_80_0  & 1)*1) >=1
 
}
rule Adware_Win32_Linkury_RS_MTB_2{
	meta:
		description = "Adware:Win32/Linkury.RS!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4c 49 4e 4b 55 52 59 49 4e 54 45 52 4e 45 54 45 58 50 4c 4f 52 45 52 42 48 4f 2e 44 4c 4c } //1 LINKURYINTERNETEXPLORERBHO.DLL
		$a_01_1 = {43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 73 00 6d 00 61 00 72 00 74 00 62 00 61 00 72 00 5c 00 } //1 C:\TEMP\smartbar\
		$a_01_2 = {53 00 65 00 61 00 72 00 63 00 68 00 2e 00 6c 00 69 00 6e 00 6b 00 75 00 72 00 79 00 2e 00 63 00 6f 00 6d 00 } //1 Search.linkury.com
		$a_01_3 = {48 00 6f 00 6d 00 65 00 50 00 61 00 67 00 65 00 55 00 52 00 4c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 } //1 HomePageURLChrome
		$a_01_4 = {4e 00 65 00 77 00 54 00 61 00 62 00 55 00 52 00 4c 00 } //1 NewTabURL
		$a_01_5 = {76 00 61 00 72 00 20 00 72 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 55 00 72 00 6c 00 4e 00 65 00 77 00 54 00 61 00 62 00 20 00 3d 00 } //1 var redirectUrlNewTab =
		$a_01_6 = {75 72 6c 73 5f 74 6f 5f 72 65 73 74 6f 72 65 5f 6f 6e 5f 73 74 61 72 74 75 70 } //1 urls_to_restore_on_startup
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}