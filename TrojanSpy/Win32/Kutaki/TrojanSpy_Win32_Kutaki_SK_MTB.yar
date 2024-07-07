
rule TrojanSpy_Win32_Kutaki_SK_MTB{
	meta:
		description = "TrojanSpy:Win32/Kutaki.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 00 61 00 76 00 65 00 72 00 62 00 72 00 6f 00 } //1 saverbro
		$a_00_1 = {61 00 63 00 68 00 69 00 62 00 61 00 74 00 33 00 32 00 31 00 58 00 } //1 achibat321X
		$a_01_2 = {53 48 44 6f 63 56 77 43 74 6c 2e 57 65 62 42 72 6f 77 73 65 72 } //1 SHDocVwCtl.WebBrowser
		$a_01_3 = {6b 69 6c 6c 65 72 6d 61 6e } //1 killerman
		$a_01_4 = {6d 75 66 75 63 6b 72 } //1 mufuckr
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}