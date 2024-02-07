
rule BrowserModifier_Win32_BazookaBar{
	meta:
		description = "BrowserModifier:Win32/BazookaBar,SIGNATURE_TYPE_PEHSTR,20 00 1e 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {75 73 65 72 73 73 74 61 72 41 72 74 69 63 73 42 61 72 2e 64 6c 6c } //0a 00  usersstarArticsBar.dll
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 42 61 7a 6f 6f 6b 61 42 61 72 } //0a 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BazookaBar
		$a_01_2 = {7d 5c 45 6e 61 62 6c 65 50 6f 70 75 70 } //01 00  }\EnablePopup
		$a_01_3 = {42 61 7a 6f 6f 6b 61 42 61 72 42 61 6e 64 } //01 00  BazookaBarBand
		$a_01_4 = {4d 00 79 00 41 00 72 00 6d 00 6f 00 72 00 79 00 2e 00 63 00 6f 00 6d 00 } //01 00  MyArmory.com
		$a_01_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 79 61 72 6d 6f 72 79 2e 63 6f 6d 2f 73 65 61 72 63 68 2f 3f 4b 65 79 77 6f 72 64 73 3d } //01 00  http://www.myarmory.com/search/?Keywords=
		$a_01_6 = {50 61 72 61 73 69 74 65 77 61 72 65 20 44 65 74 65 63 74 6f 72 } //00 00  Parasiteware Detector
	condition:
		any of ($a_*)
 
}