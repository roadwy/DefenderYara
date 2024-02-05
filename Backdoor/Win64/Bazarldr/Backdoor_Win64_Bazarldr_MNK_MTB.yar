
rule Backdoor_Win64_Bazarldr_MNK_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.MNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {ba 0a 1a 00 00 41 b8 0b 00 00 00 48 8d 0d 7a b2 ff ff ff 15 90 02 04 48 8b f8 48 8b d0 48 8d 0d 67 b2 ff ff ff 15 90 02 04 48 8b f0 48 8b d7 48 8d 0d 54 b2 ff ff ff 15 90 02 04 89 44 24 50 90 00 } //01 00 
		$a_03_1 = {8b d0 33 c9 44 8d 49 90 02 01 41 b8 90 02 02 00 00 ff 15 90 02 04 48 8b f8 44 8b 44 24 50 48 8b d6 48 8b c8 e8 90 02 03 00 90 00 } //01 00 
		$a_03_2 = {48 8b 44 0a f8 4c 8b 54 0a f0 48 83 e9 90 02 01 48 89 41 18 4c 89 51 10 48 8b 44 0a 08 4c 8b 14 0a 49 ff c9 48 89 41 08 4c 89 11 75 d5 90 00 } //01 00 
		$a_03_3 = {41 8a 00 48 ff c2 49 ff c8 48 3b d3 42 88 44 32 90 02 01 7c ed 90 00 } //01 00 
		$a_03_4 = {48 8b 4c 24 50 45 33 c9 89 44 24 30 45 8d 41 01 33 d2 48 89 74 24 28 48 89 6c 24 20 ff 15 90 02 04 85 c0 0f 95 c0 eb 02 90 00 } //00 00 
		$a_00_5 = {5d 04 00 } //00 dc 
	condition:
		any of ($a_*)
 
}