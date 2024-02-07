
rule Trojan_Win32_Startpage_PN{
	meta:
		description = "Trojan:Win32/Startpage.PN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 73 65 72 5f 70 72 65 66 28 25 63 62 72 6f 77 73 65 72 2e 73 74 61 72 74 75 70 2e 68 6f 6d 65 70 61 67 65 } //01 00  user_pref(%cbrowser.startup.homepage
		$a_00_1 = {6d 6f 7a 69 6c 6c 61 5c 66 69 72 65 66 6f 78 5c 70 72 6f 66 69 6c 65 73 5c 2a } //01 00  mozilla\firefox\profiles\*
		$a_03_2 = {ff 74 24 20 ff 15 90 01 04 ff 74 24 0c ff 15 90 01 04 83 c3 04 8b c3 39 3b 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}