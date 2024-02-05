
rule Trojan_Win32_Startpage_SQ{
	meta:
		description = "Trojan:Win32/Startpage.SQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 08 40 84 c9 75 90 02 05 2b c2 50 90 02 04 68 90 01 04 6a 01 56 68 90 01 05 ff 15 90 01 04 85 c0 90 00 } //01 00 
		$a_03_1 = {68 57 00 07 80 e8 90 01 04 55 8b 6c 90 01 02 56 55 53 e8 90 01 04 8b f0 8b 07 8b 50 f8 83 e8 10 90 00 } //01 00 
		$a_00_2 = {69 6c 63 2e 6e 62 7a 2e 63 6f 2e 6b 72 2f 69 6e 73 74 61 6c 6c 2e 61 73 70 3f 69 64 3d 31 38 36 26 6d 61 63 3d 25 73 } //01 00 
		$a_00_3 = {64 69 73 6b 6d 61 6e 69 61 2e 63 6f 2e 6b 72 2f 70 72 6f 67 72 61 6d 2f 79 61 68 6f 6f 5f } //00 00 
	condition:
		any of ($a_*)
 
}