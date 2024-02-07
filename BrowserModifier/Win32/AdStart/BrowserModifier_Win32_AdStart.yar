
rule BrowserModifier_Win32_AdStart{
	meta:
		description = "BrowserModifier:Win32/AdStart,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 57 69 6e 33 32 2e 44 4c 4c } //03 00  SWin32.DLL
		$a_01_1 = {49 45 45 6e 68 61 6e 63 65 72 } //03 00  IEEnhancer
		$a_01_2 = {2f 61 64 6c 41 70 70 2f } //03 00  /adlApp/
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 79 30 33 36 } //03 00  SOFTWARE\y036
		$a_01_4 = {67 65 74 5f 75 69 64 2e 61 73 70 } //01 00  get_uid.asp
		$a_01_5 = {6d 61 74 63 68 5f 74 79 70 65 } //03 00  match_type
		$a_01_6 = {73 70 33 32 2e 78 6d 6c } //02 00  sp32.xml
		$a_01_7 = {73 65 61 72 63 68 5f 74 72 69 67 67 65 72 } //01 00  search_trigger
		$a_01_8 = {70 6f 70 75 70 2e 68 74 6d 6c } //01 00  popup.html
		$a_01_9 = {6b 65 79 5f 62 65 67 69 6e } //01 00  key_begin
		$a_01_10 = {73 65 61 72 63 68 5f 74 65 72 6d } //00 00  search_term
	condition:
		any of ($a_*)
 
}