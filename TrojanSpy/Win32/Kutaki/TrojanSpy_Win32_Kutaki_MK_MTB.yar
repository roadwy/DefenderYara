
rule TrojanSpy_Win32_Kutaki_MK_MTB{
	meta:
		description = "TrojanSpy:Win32/Kutaki.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 00 20 00 20 00 75 00 20 00 20 00 72 00 20 00 20 00 65 00 } //01 00  S  u  r  e
		$a_00_1 = {73 00 61 00 76 00 65 00 72 00 62 00 72 00 6f 00 } //01 00  saverbro
		$a_00_2 = {57 00 61 00 6e 00 20 00 74 00 20 00 54 00 6f 00 20 00 20 00 43 00 6c 00 65 00 61 00 72 00 20 00 20 00 4c 00 6f 00 67 00 20 00 3f 00 3f 00 } //01 00  Wan t To  Clear  Log ??
		$a_00_3 = {61 00 63 00 68 00 69 00 62 00 61 00 74 00 33 00 32 00 31 00 58 00 } //01 00  achibat321X
		$a_01_4 = {53 48 44 6f 63 56 77 43 74 6c 2e 57 65 62 42 72 6f 77 73 65 72 } //01 00  SHDocVwCtl.WebBrowser
		$a_01_5 = {6b 69 6c 6c 65 72 6d 61 6e } //01 00  killerman
		$a_01_6 = {6d 75 66 75 63 6b 72 } //00 00  mufuckr
		$a_00_7 = {5d 04 00 00 85 } //3d 04 
	condition:
		any of ($a_*)
 
}