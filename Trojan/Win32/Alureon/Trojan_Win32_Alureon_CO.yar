
rule Trojan_Win32_Alureon_CO{
	meta:
		description = "Trojan:Win32/Alureon.CO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 44 24 04 8a d1 03 c1 80 c2 90 01 01 30 10 41 3b 4c 24 08 72 ec 90 00 } //01 00 
		$a_03_1 = {8b 48 3c 8d 4c 01 04 90 03 06 09 66 81 49 12 00 20 ba 00 20 00 00 66 09 51 12 90 00 } //02 00 
		$a_01_2 = {c6 45 eb 23 c6 45 ec 39 c6 45 ed 35 c6 45 ee 36 c6 45 ef 1f } //02 00 
		$a_01_3 = {3d 57 01 00 c0 75 0f } //01 00 
		$a_01_4 = {c6 45 f0 e9 ab 56 e8 } //02 00 
		$a_01_5 = {76 15 8b 44 24 04 8a d1 02 54 24 0c 03 c1 30 10 41 } //00 00 
	condition:
		any of ($a_*)
 
}