
rule Trojan_Win32_Webprefix{
	meta:
		description = "Trojan:Win32/Webprefix,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 04 00 "
		
	strings :
		$a_01_0 = {31 68 70 3d 73 74 65 75 64 66 2f 61 72 00 00 00 25 30 38 58 2d 25 30 34 58 2d 25 30 34 58 2d 25 30 32 58 25 30 32 58 2d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 00 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 00 00 57 65 62 50 72 65 66 69 78 00 } //02 00 
		$a_01_1 = {4f 66 66 6c 69 6e 65 20 46 6f 6c 64 65 72 } //02 00  Offline Folder
		$a_01_2 = {26 6f 73 3d 25 73 26 77 70 61 } //00 00  &os=%s&wpa
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Webprefix_2{
	meta:
		description = "Trojan:Win32/Webprefix,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 68 70 3d 73 74 65 75 64 66 2f 61 72 } //01 00  1hp=steudf/ar
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //01 00  Software\Microsoft\Internet Explorer\Main
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 25 73 } //05 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\%s
		$a_01_3 = {57 65 62 50 72 65 66 69 78 } //01 00  WebPrefix
		$a_01_4 = {43 4c 53 49 44 5c 25 73 5c 49 6e 70 72 6f 63 53 65 72 76 65 72 33 32 } //02 00  CLSID\%s\InprocServer32
		$a_01_5 = {4f 66 66 6c 69 6e 65 20 46 6f 6c 64 65 72 } //02 00  Offline Folder
		$a_01_6 = {26 6f 73 3d 25 73 26 77 70 61 } //03 00  &os=%s&wpa
		$a_01_7 = {21 41 44 57 41 52 45 5f 53 46 58 21 } //01 00  !ADWARE_SFX!
		$a_01_8 = {45 6e 61 62 6c 65 20 42 72 6f 77 73 65 72 20 45 78 74 65 6e 73 69 6f 6e 73 } //00 00  Enable Browser Extensions
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Webprefix_3{
	meta:
		description = "Trojan:Win32/Webprefix,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 65 62 50 72 65 66 69 78 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //01 00 
		$a_01_1 = {26 6f 73 3d 25 73 26 77 70 61 3d 25 73 26 61 67 3d 25 73 26 75 6d 3d 25 73 } //01 00  &os=%s&wpa=%s&ag=%s&um=%s
		$a_01_2 = {3d 73 74 65 75 64 66 2f 61 72 } //01 00  =steudf/ar
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4d 65 64 69 61 5c 57 4d 53 44 4b 5c 47 65 6e 65 72 61 6c } //00 00  Software\Microsoft\Windows Media\WMSDK\General
	condition:
		any of ($a_*)
 
}