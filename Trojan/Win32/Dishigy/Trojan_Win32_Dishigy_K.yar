
rule Trojan_Win32_Dishigy_K{
	meta:
		description = "Trojan:Win32/Dishigy.K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1 } //01 00 
		$a_03_1 = {bf 01 00 00 00 8b 45 90 01 01 90 17 03 06 05 05 33 db 8a 5c 38 ff 0f b6 5c 38 ff 0f b7 5c 78 fe 33 5d 90 01 01 3b 5d 90 01 01 7f 0b 81 c3 ff 00 00 00 90 00 } //01 00 
		$a_00_2 = {71 00 75 00 69 00 6e 00 61 00 73 00 20 00 56 00 69 00 72 00 74 00 75 00 61 00 69 00 73 00 2e 00 } //00 00  quinas Virtuais.
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dishigy_K_2{
	meta:
		description = "Trojan:Win32/Dishigy.K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 b9 0a 00 00 00 66 ba 58 56 ed } //01 00 
		$a_01_1 = {0f b7 5c 78 fe 33 5d e0 3b 5d e4 7f 0b 81 c3 ff 00 00 00 2b 5d e4 eb 03 2b 5d e4 8d 45 c8 8b d3 e8 } //01 00 
		$a_03_2 = {74 17 8d 55 f4 b8 90 01 04 e8 90 01 04 8b 55 f4 8b c3 e8 90 01 04 8d 55 f0 a1 90 01 04 e8 90 01 04 8b 45 f0 50 8d 55 ec b8 90 01 04 e8 90 01 04 8b 45 ec 5a e8 90 01 04 84 c0 74 17 8d 55 e8 b8 90 01 04 e8 90 00 } //00 00 
		$a_00_3 = {87 10 } //00 00 
	condition:
		any of ($a_*)
 
}