
rule Trojan_Win32_Lokijan_A{
	meta:
		description = "Trojan:Win32/Lokijan.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 8b 55 0c 81 31 90 01 04 f7 11 83 c1 04 4a 75 90 00 } //01 00 
		$a_01_1 = {8b 4d 0c 41 33 d2 f7 f1 92 3b 45 08 } //02 00 
		$a_01_2 = {33 c0 40 c1 e0 06 8d 40 f0 64 8b 00 } //02 00 
		$a_03_3 = {68 00 1a 40 00 e8 90 01 02 ff ff a3 90 01 02 40 00 6a 90 01 01 68 90 01 01 1a 40 00 e8 90 01 02 ff ff a3 90 01 02 40 00 6a 90 01 01 68 90 01 01 1a 40 00 90 00 } //00 00 
		$a_00_4 = {5d 04 00 } //00 88 
	condition:
		any of ($a_*)
 
}