
rule Trojan_Win64_IcedID_ME_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 45 48 b9 90 01 04 2b c8 8b 45 48 2b c8 83 c1 1c 89 4d 48 8a 45 50 88 02 44 89 65 48 44 89 6d 50 8b 45 48 23 c6 7d 90 00 } //01 00 
		$a_01_1 = {44 6c 6c 4d 61 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_ME_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 ff c0 41 f7 ec c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 41 8b c4 41 ff c4 6b d2 90 01 01 2b c2 48 63 c8 48 8b 44 24 90 01 01 42 0f b6 8c 31 90 01 04 41 32 4c 00 ff 43 88 4c 18 ff 44 3b 64 24 20 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_ME_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {48 8b c6 48 2b c7 48 c1 f8 02 48 83 f8 01 73 5e 49 2b fe 48 c1 ff 02 48 8b c1 48 2b c7 48 83 f8 01 72 7a 48 8d 57 01 49 2b f6 48 c1 fe 02 48 8b c6 48 d1 e8 48 2b c8 } //03 00 
		$a_81_1 = {63 73 62 75 71 79 61 73 6e } //03 00 
		$a_81_2 = {63 77 6c 76 71 70 71 70 69 63 64 64 66 70 } //03 00 
		$a_81_3 = {64 7a 78 76 65 72 76 65 64 67 79 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_ME_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {48 8b 54 24 20 88 04 0a eb 11 e9 7a ff ff ff 89 04 24 8b 44 24 28 e9 63 ff ff ff 8b 04 24 ff c0 eb ed eb 60 48 ff c0 48 89 04 24 3a c0 74 2e 88 08 48 8b 04 24 3a ff 74 eb 48 89 44 24 08 48 8b 44 24 30 eb 4e } //0a 00 
		$a_01_1 = {48 8b 44 24 20 48 89 04 24 3a d2 74 da 48 ff c8 48 89 44 24 30 eb 31 eb 3d 48 ff c0 48 89 04 24 66 3b d2 74 ce 4c 89 44 24 18 48 89 54 24 10 3a c9 74 9a 88 08 48 8b 04 24 3a c9 74 dc } //14 00 
		$a_01_2 = {79 67 73 66 61 62 61 79 75 73 66 6a 6e 61 73 66 6b 61 } //00 00 
	condition:
		any of ($a_*)
 
}