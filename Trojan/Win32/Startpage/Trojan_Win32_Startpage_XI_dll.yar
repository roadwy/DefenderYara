
rule Trojan_Win32_Startpage_XI_dll{
	meta:
		description = "Trojan:Win32/Startpage.XI!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 35 6c 30 2e 6e 65 74 2f 90 09 03 00 67 6f 90 00 } //01 00 
		$a_03_1 = {5c cf d4 ca be d7 c0 c3 e6 2e 73 63 66 00 90 01 34 43 6f 6d 6d 61 6e 64 3d 54 6f 67 67 6c 65 44 65 73 6b 74 6f 70 20 90 00 } //01 00 
		$a_01_2 = {7c 53 61 66 61 72 69 2e 65 78 65 7c 4d 61 78 74 68 6f 6e 2e 65 78 65 7c 53 6f 67 6f 75 45 78 70 6c 6f 72 65 72 2e 65 78 65 7c 54 68 65 57 6f 72 6c 64 2e 65 78 65 7c 54 54 72 61 76 65 6c 65 72 2e 65 78 65 7c 33 36 30 53 45 2e 65 78 65 7c 63 68 72 6f 6d 65 2e 65 78 65 7c 47 72 65 65 6e 42 72 6f 77 73 65 72 2e 65 78 65 7c 6f 70 65 72 61 2e 65 78 65 7c 66 69 72 65 66 6f 78 2e 65 78 65 7c } //00 00  |Safari.exe|Maxthon.exe|SogouExplorer.exe|TheWorld.exe|TTraveler.exe|360SE.exe|chrome.exe|GreenBrowser.exe|opera.exe|firefox.exe|
	condition:
		any of ($a_*)
 
}