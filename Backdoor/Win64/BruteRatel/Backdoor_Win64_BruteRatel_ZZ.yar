
rule Backdoor_Win64_BruteRatel_ZZ{
	meta:
		description = "Backdoor:Win64/BruteRatel.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 79 ff cc 74 58 45 85 c0 75 04 48 83 e9 20 44 8a 09 41 80 f9 e9 74 0a 44 8a 41 03 41 80 f8 e9 75 07 ff c2 45 31 c0 eb d7 } //01 00 
		$a_01_1 = {31 c0 41 80 f9 4c 75 2f 80 79 01 8b 75 29 80 79 02 d1 75 21 41 80 f8 b8 75 1b 80 79 06 00 75 17 0f b6 41 05 c1 e0 08 41 89 c0 0f b6 41 04 44 09 c0 01 d0 eb 02 31 c0 c3 } //02 00 
	condition:
		any of ($a_*)
 
}