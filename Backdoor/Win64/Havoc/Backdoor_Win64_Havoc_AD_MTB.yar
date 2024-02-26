
rule Backdoor_Win64_Havoc_AD_MTB{
	meta:
		description = "Backdoor:Win64/Havoc.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_03_1 = {41 83 e9 20 6b c0 21 45 0f b6 c9 49 ff c2 44 01 c8 90 13 45 8a 0a 85 d2 75 06 45 84 c9 90 13 41 80 f9 60 90 13 6b c0 21 90 00 } //00 00 
		$a_00_2 = {5d 04 00 00 94 44 06 80 5c 29 00 00 95 44 06 80 00 00 01 00 08 00 13 00 ac 21 47 6c 75 70 74 65 62 61 2e 4d 42 4b 4f 21 4d 54 42 00 00 01 40 05 82 70 00 04 00 78 3b 00 00 01 00 01 00 01 00 00 01 00 2e 01 83 45 f4 01 8b 45 fc 8b 55 f4 8d 1c 10 ba 0c a0 40 00 8b 45 f4 8a 44 02 ff 88 43 ff 3b 4d f4 77 } //df 6a 
	condition:
		any of ($a_*)
 
}