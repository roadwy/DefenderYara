
rule Backdoor_Win64_BruteRatel_AA_MTB{
	meta:
		description = "Backdoor:Win64/BruteRatel.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 83 e4 f0 68 90 01 04 5a e8 00 00 00 00 59 48 01 d1 48 83 c1 90 01 01 ff d1 90 00 } //01 00 
		$a_03_1 = {41 59 e8 00 00 00 00 41 58 4d 01 c8 49 83 c0 90 01 01 41 ff d0 90 0a 20 00 59 68 90 01 04 41 59 90 00 } //01 00 
		$a_03_2 = {0f be 11 45 31 c0 84 d2 74 90 01 01 66 0f 1f 44 00 00 44 89 c0 48 83 c1 01 c1 e0 90 01 01 44 01 c0 0d 00 00 80 02 44 8d 04 02 0f be 11 84 d2 75 90 01 01 44 89 c0 90 00 } //02 00 
	condition:
		any of ($a_*)
 
}