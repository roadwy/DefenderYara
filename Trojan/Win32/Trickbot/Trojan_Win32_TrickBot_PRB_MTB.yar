
rule Trojan_Win32_TrickBot_PRB_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.PRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 30 00 00 53 6a 00 ff d5 8b 77 54 8b d8 8b 44 24 5c 33 c9 89 44 24 14 8b d3 33 c0 89 5c 24 18 40 89 44 24 24 85 f6 74 } //01 00 
		$a_01_1 = {8b 51 f8 48 8b 31 03 d3 8b 69 fc 03 f7 89 44 24 5c 85 ed 74 0f 8a 06 88 02 42 46 83 ed 01 75 f5 8b 44 24 5c 83 c1 28 85 c0 75 d5 } //01 00 
		$a_03_2 = {e8 00 00 00 00 58 89 c3 05 90 01 04 81 c3 90 01 04 68 90 01 04 68 90 01 04 53 68 90 01 04 50 e8 04 00 00 00 83 c4 14 c3 83 ec 48 83 64 24 18 00 b9 90 01 04 53 55 56 57 33 f6 e8 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}