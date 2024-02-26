
rule BrowserModifier_Win32_Xiazai{
	meta:
		description = "BrowserModifier:Win32/Xiazai,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2f 64 6f 77 6e 2e 78 69 61 7a 61 69 } //01 00  /down.xiazai
		$a_01_1 = {53 65 74 53 68 6f 72 74 43 75 74 41 72 67 73 } //01 00  SetShortCutArgs
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //01 00  Software\Policies\Microsoft\Internet Explorer\Main
		$a_01_3 = {24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69 } //00 00  $\wininit.ini
		$a_00_4 = {7e 15 00 } //00 20 
	condition:
		any of ($a_*)
 
}