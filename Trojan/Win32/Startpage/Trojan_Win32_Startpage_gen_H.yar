
rule Trojan_Win32_Startpage_gen_H{
	meta:
		description = "Trojan:Win32/Startpage.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //0a 00  Software\Microsoft\Internet Explorer\Main
		$a_00_1 = {53 74 61 72 74 20 50 61 67 65 } //05 00  Start Page
		$a_00_2 = {61 62 6f 75 74 3a 62 6c 61 6e 6b } //05 00  about:blank
		$a_01_3 = {68 61 6f 31 32 33 } //05 00  hao123
		$a_00_4 = {53 74 61 72 74 53 65 72 76 69 63 65 41 } //05 00  StartServiceA
		$a_01_5 = {70 61 72 61 75 64 69 6f } //01 00  paraudio
		$a_01_6 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6b 7a 64 68 2e 63 6f 6d 2f } //01 00  http://www.kzdh.com/
		$a_01_7 = {77 77 77 2e 32 36 35 2e 63 6f 6d } //00 00  www.265.com
	condition:
		any of ($a_*)
 
}