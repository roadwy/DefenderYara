
rule TrojanDownloader_Win32_Zlob_ZWV{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ZWV,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {bb 65 00 00 00 e8 ?? ?? ff ff 80 3e 00 75 0f e8 ?? ?? ff ff 6a 0a e8 ?? ?? ff ff 4b 75 e7 c6 06 00 bb 11 27 00 00 e8 ?? ?? ff ff 80 3e 00 75 0a 6a 0a e8 ?? ?? ff ff } //2
		$a_00_1 = {43 3a 5c 54 45 4d 50 5c 62 75 64 67 65 74 2e 78 70 69 } //2 C:\TEMP\budget.xpi
		$a_00_2 = {4d 6f 7a 69 6c 6c 61 55 49 57 69 6e 64 6f 77 43 6c 61 73 73 } //1 MozillaUIWindowClass
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 6f 7a 69 6c 6c 61 5c 4d 6f 7a 69 6c 6c 61 20 46 69 72 65 66 6f 78 } //1 SOFTWARE\Mozilla\Mozilla Firefox
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}