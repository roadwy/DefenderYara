
rule Trojan_Win32_Startpage_XM{
	meta:
		description = "Trojan:Win32/Startpage.XM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 00 77 00 78 00 79 00 78 00 2e 00 63 00 6f 00 6d 00 2f 00 } //01 00 
		$a_01_1 = {6d 00 6d 00 74 00 70 00 35 00 2e 00 69 00 6e 00 66 00 6f 00 2f 00 } //01 00 
		$a_01_2 = {c4 e3 d5 fd d4 da bd f8 d0 d0 b0 b2 d7 b0 c9 ab c7 e9 b5 e7 d3 b0 b2 a5 b7 c5 c6 f7 b5 da d2 bb b2 bd } //01 00 
		$a_01_3 = {35 00 39 00 36 00 38 00 38 00 5c 00 56 00 42 00 ad 64 3e 65 68 56 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}