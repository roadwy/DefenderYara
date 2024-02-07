
rule BrowserModifier_Win32_Elopesmut{
	meta:
		description = "BrowserModifier:Win32/Elopesmut,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {2d 00 2d 00 61 00 70 00 70 00 3d 00 25 00 73 00 77 00 69 00 6e 00 64 00 6f 00 77 00 2d 00 70 00 72 00 6f 00 6d 00 6f 00 2e 00 68 00 74 00 6d 00 6c 00 } //02 00  --app=%swindow-promo.html
		$a_01_1 = {67 00 61 00 61 00 67 00 68 00 6b 00 68 00 67 00 68 00 6e 00 69 00 6a 00 70 00 65 00 64 00 6b 00 6e 00 6f 00 69 00 68 00 67 00 65 00 6c 00 66 00 69 00 62 00 69 00 64 00 6a 00 63 00 63 00 6e 00 } //01 00  gaaghkhghnijpedknoihgelfibidjccn
		$a_01_2 = {43 00 68 00 72 00 6f 00 6d 00 65 00 5f 00 57 00 69 00 64 00 67 00 65 00 74 00 57 00 69 00 6e 00 5f 00 31 00 } //00 00  Chrome_WidgetWin_1
		$a_00_3 = {78 0f } //01 00  ླྀ
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Elopesmut_2{
	meta:
		description = "BrowserModifier:Win32/Elopesmut,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {45 00 6d 00 6f 00 74 00 69 00 70 00 6c 00 75 00 73 00 20 00 57 00 65 00 62 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 } //0a 00  Emotiplus WebInstaller
		$a_01_1 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 44 00 65 00 76 00 65 00 6c 00 6f 00 70 00 6d 00 65 00 6e 00 74 00 20 00 4d 00 65 00 64 00 69 00 61 00 20 00 37 00 33 00 } //02 00 
		$a_01_2 = {2f 00 77 00 69 00 6e 00 64 00 6f 00 77 00 2d 00 70 00 72 00 6f 00 6d 00 6f 00 2e 00 63 00 6f 00 6d 00 2f 00 63 00 6f 00 6e 00 64 00 69 00 74 00 69 00 6f 00 6e 00 2d 00 67 00 } //01 00  /window-promo.com/condition-g
		$a_01_3 = {5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 41 00 70 00 70 00 72 00 6f 00 76 00 65 00 64 00 20 00 45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 } //00 00  \Internet Explorer\Approved Extensions
		$a_00_4 = {60 23 } //00 00  `#
	condition:
		any of ($a_*)
 
}