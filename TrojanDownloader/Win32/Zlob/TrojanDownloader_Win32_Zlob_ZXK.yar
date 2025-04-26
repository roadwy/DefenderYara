
rule TrojanDownloader_Win32_Zlob_ZXK{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ZXK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {61 76 61 73 74 21 [0-03] 6b 69 6e } //1
		$a_01_1 = {66 74 68 65 77 6f 72 6c 64 } //1 ftheworld
		$a_01_2 = {33 39 34 41 33 } //1 394A3
		$a_01_3 = {56 43 32 30 58 43 30 30 } //1 VC20XC00
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}