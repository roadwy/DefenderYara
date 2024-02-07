
rule BrowserModifier_Win32_ShieldSoftCby{
	meta:
		description = "BrowserModifier:Win32/ShieldSoftCby,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 53 65 74 74 69 6e 67 73 5c 46 46 44 65 66 53 65 61 72 63 68 2e 74 78 74 } //01 00  \Settings\FFDefSearch.txt
		$a_01_1 = {26 72 3d 37 30 30 31 26 67 65 6f 3d 55 53 26 70 74 61 67 3d 59 41 48 4f 4f 26 61 66 66 69 64 3d 79 61 68 6f 6f 26 61 70 70 3d 73 68 69 65 6c 64 } //00 00  &r=7001&geo=US&ptag=YAHOO&affid=yahoo&app=shield
		$a_00_2 = {78 } //4e 01  x
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_ShieldSoftCby_2{
	meta:
		description = "BrowserModifier:Win32/ShieldSoftCby,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 00 53 00 68 00 69 00 65 00 6c 00 64 00 53 00 6f 00 66 00 74 00 5c 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 55 00 73 00 65 00 72 00 43 00 68 00 72 00 6f 00 6d 00 65 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 2e 00 74 00 78 00 74 00 } //01 00  \ShieldSoft\Settings\UserChromeSettings.txt
		$a_01_1 = {42 79 20 6d 6f 64 69 66 79 69 6e 67 20 74 68 69 73 20 66 69 6c 65 2c 20 49 20 61 67 72 65 65 20 74 68 61 74 20 49 20 61 6d 20 64 6f 69 6e 67 20 73 6f 20 6f 6e 6c 79 20 77 69 74 68 69 6e 20 46 69 72 65 66 6f 78 20 69 74 73 65 6c 66 2c 20 75 73 69 6e 67 20 6f 66 66 69 63 69 61 6c 2c 20 75 73 65 72 2d 64 72 69 76 65 6e 20 73 65 61 72 63 68 20 65 6e 67 69 6e 65 20 73 65 6c 65 63 74 } //01 00  By modifying this file, I agree that I am doing so only within Firefox itself, using official, user-driven search engine select
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 53 00 65 00 61 00 72 00 63 00 68 00 53 00 63 00 6f 00 70 00 65 00 73 00 } //00 00  Software\Microsoft\Internet Explorer\SearchScopes
		$a_00_3 = {60 0d } //00 00  ൠ
	condition:
		any of ($a_*)
 
}