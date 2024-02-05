
rule Trojan_Win32_Startpage_UI{
	meta:
		description = "Trojan:Win32/Startpage.UI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba 74 20 45 78 89 11 83 c3 04 03 cb 6b db 00 ba 70 6c 6f 72 89 11 83 c3 04 03 cb 6b db 00 ba 65 72 5c 5c 89 11 83 c3 04 03 cb 6b db 00 ba 4d 61 69 6e } //01 00 
		$a_03_1 = {65 8b e5 5d c3 90 09 1b 00 c6 05 90 01 04 68 c6 05 90 01 04 74 c6 05 90 01 04 2f c6 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}