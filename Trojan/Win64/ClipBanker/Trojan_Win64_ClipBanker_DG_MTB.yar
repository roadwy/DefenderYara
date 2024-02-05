
rule Trojan_Win64_ClipBanker_DG_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {48 83 ec 30 48 8b f9 49 8b f0 48 8b 49 10 4c 8b 47 18 49 8b c0 48 2b c1 48 3b f0 77 3f 48 89 5c 24 40 48 8d 04 31 48 89 47 10 48 8b c7 49 83 f8 10 72 03 } //03 00 
		$a_81_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 43 6c 69 70 70 65 72 } //03 00 
		$a_81_2 = {42 54 43 20 43 6c 69 70 70 65 72 2e 70 64 62 } //03 00 
		$a_81_3 = {62 69 74 63 6f 69 6e 63 61 73 68 7c 62 63 68 72 65 67 7c 62 63 68 74 65 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_ClipBanker_DG_MTB_2{
	meta:
		description = "Trojan:Win64/ClipBanker.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_81_0 = {5b 31 33 5d 5b 61 2d 6b 6d 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 31 2d 39 5d 7b 32 35 2c 33 34 7d } //03 00 
		$a_81_1 = {41 50 50 44 41 54 41 } //03 00 
		$a_81_2 = {5c 57 69 6e 64 6f 77 73 6c 69 62 2e 65 78 65 } //03 00 
		$a_81_3 = {33 45 39 46 74 69 42 41 77 50 78 62 46 66 6d 68 77 37 62 4e 4d 66 6d 53 79 73 72 62 63 4b 67 58 4e 43 } //03 00 
		$a_81_4 = {48 69 64 65 6e 50 72 6f 63 65 73 2e 70 64 62 } //03 00 
		$a_81_5 = {2d 66 6f 6f 62 61 72 } //00 00 
	condition:
		any of ($a_*)
 
}