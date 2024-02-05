
rule Trojan_Win32_Alureon_BJ{
	meta:
		description = "Trojan:Win32/Alureon.BJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {76 10 8a d1 02 54 24 08 30 14 01 41 3b 4c 24 04 72 f0 } //02 00 
		$a_03_1 = {75 f6 8d 45 08 50 68 13 01 00 00 90 09 22 00 c6 85 90 01 04 e9 90 00 } //02 00 
		$a_01_2 = {68 44 44 41 4d 68 58 4b 4e 53 } //01 00 
		$a_01_3 = {6a 73 2e 70 68 70 3f 75 3d 25 73 } //01 00 
		$a_01_4 = {6b 65 79 77 6f 72 64 20 3d 20 52 65 67 45 78 70 2e 24 31 3b } //00 00 
	condition:
		any of ($a_*)
 
}