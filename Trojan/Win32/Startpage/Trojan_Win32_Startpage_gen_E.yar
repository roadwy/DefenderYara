
rule Trojan_Win32_Startpage_gen_E{
	meta:
		description = "Trojan:Win32/Startpage.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1b 00 0c 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //05 00  SOFTWARE\Microsoft\Internet Explorer\Main
		$a_01_1 = {5c 65 70 6c 72 72 39 2e 64 6c 6c } //03 00  \eplrr9.dll
		$a_01_2 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //03 00  GetSystemDirectoryA
		$a_01_3 = {70 64 78 2e 64 6c 6c } //01 00  pdx.dll
		$a_01_4 = {53 65 61 72 63 68 20 50 61 67 65 } //01 00  Search Page
		$a_01_5 = {4c 6f 63 61 6c 20 50 61 67 65 } //01 00  Local Page
		$a_00_6 = {53 74 61 72 74 20 50 61 67 65 } //01 00  Start Page
		$a_00_7 = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d } //01 00  [InternetShortcut]
		$a_01_8 = {55 52 4c 3d 25 73 } //01 00  URL=%s
		$a_01_9 = {46 69 72 73 74 20 48 6f 6d 65 20 50 61 67 65 } //01 00  First Home Page
		$a_01_10 = {44 65 66 61 75 6c 74 5f 53 65 61 72 63 68 5f 55 52 4c } //01 00  Default_Search_URL
		$a_01_11 = {44 65 66 61 75 6c 74 5f 50 61 67 65 5f 55 52 4c } //00 00  Default_Page_URL
	condition:
		any of ($a_*)
 
}