
rule Trojan_Win32_Rombertik_D{
	meta:
		description = "Trojan:Win32/Rombertik.D,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {2b df c6 07 e9 83 eb 05 89 5f 01 2b f8 83 ef 05 c6 04 06 e9 89 7c 06 01 } //05 00 
		$a_01_1 = {84 d2 74 0b 83 7c 81 04 00 74 1b 84 d2 75 07 83 7c 81 04 00 75 10 40 83 f8 23 72 de } //03 00 
		$a_01_2 = {be 1e 7c e8 0b 00 eb fe b4 0e b7 00 b3 1f cd 10 c3 8a 04 46 08 c0 74 05 e8 ed ff eb f4 c3 43 61 72 62 6f 6e 20 63 72 61 } //01 00 
		$a_01_3 = {61 57 56 34 63 47 78 76 63 6d 55 75 5a 58 68 6c } //01 00 
		$a_01_4 = {5a 58 68 77 62 47 39 79 5a 58 49 75 5a 58 68 6c } //00 00 
		$a_00_5 = {87 10 00 00 ee 01 05 36 02 18 } //12 62 
	condition:
		any of ($a_*)
 
}