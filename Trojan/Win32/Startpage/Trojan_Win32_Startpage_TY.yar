
rule Trojan_Win32_Startpage_TY{
	meta:
		description = "Trojan:Win32/Startpage.TY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {51 75 69 63 6b 20 4c 61 75 6e 63 68 90 02 03 68 74 74 70 3a 2f 2f 77 77 77 2e 31 31 34 2e 90 00 } //01 00 
		$a_01_1 = {74 65 73 74 2e 31 31 34 2e 63 6f 6d 2e 63 6e } //01 00  test.114.com.cn
		$a_01_2 = {5c 57 69 6e 52 41 52 5c 69 2e 69 63 6f } //01 00  \WinRAR\i.ico
		$a_01_3 = {ce d2 b5 c4 b8 f6 d0 d4 b5 bc ba bd ca d7 d2 b3 2e 6c 6e 6b 00 } //01 00 
		$a_01_4 = {68 04 01 00 00 50 6a ff 51 6a 00 6a 00 ff d6 8b 44 24 30 8d 8c 24 d0 01 00 00 6a 02 51 8b 10 50 ff 52 18 8b 44 24 20 } //00 00 
	condition:
		any of ($a_*)
 
}