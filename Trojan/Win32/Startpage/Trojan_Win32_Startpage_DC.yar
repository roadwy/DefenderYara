
rule Trojan_Win32_Startpage_DC{
	meta:
		description = "Trojan:Win32/Startpage.DC,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 06 00 00 03 00 "
		
	strings :
		$a_00_0 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //03 00  \Software\Microsoft\Internet Explorer\Main
		$a_00_1 = {77 77 77 2e 61 70 65 68 61 2e 72 75 } //03 00  www.apeha.ru
		$a_00_2 = {53 74 61 72 74 20 50 61 67 65 } //03 00  Start Page
		$a_00_3 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 41 } //03 00  RegSetValueExA
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_5 = {b9 60 e8 43 00 ba 78 e8 43 00 8b 45 f8 e8 44 fd ff ff } //00 00 
	condition:
		any of ($a_*)
 
}