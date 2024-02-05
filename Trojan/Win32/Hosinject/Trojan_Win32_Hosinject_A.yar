
rule Trojan_Win32_Hosinject_A{
	meta:
		description = "Trojan:Win32/Hosinject.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 b2 6e b1 65 b3 72 b0 64 6a 01 68 90 01 04 c6 44 24 3c 43 c6 44 24 3d 6f 88 54 24 3e c6 44 24 3f 74 88 4c 24 40 88 54 24 41 c6 44 24 42 74 c6 44 24 44 54 c6 44 24 45 79 88 4c 24 47 90 00 } //01 00 
		$a_01_1 = {6a 04 50 6a 02 56 ff d7 8d 4c 24 5c 6a 04 51 6a 07 56 ff d7 8d 54 24 5c 6a 04 52 6a 08 56 ff d7 } //01 00 
		$a_01_2 = {8b 94 24 c0 00 00 00 8d 44 24 0c 53 8b 1d 28 90 40 00 50 8d 4c 24 18 6a 04 83 c2 08 51 52 56 ff d3 } //00 00 
	condition:
		any of ($a_*)
 
}