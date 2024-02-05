
rule Trojan_Win32_Gozi_GT_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {57 8b 7c 24 90 01 01 2b fd 8a 04 2f 8d 4a 90 01 01 4e 88 45 00 8b 15 90 01 04 03 ce 6b c1 90 01 01 45 6a db 59 2b c8 03 d1 89 15 90 01 04 85 f6 75 90 01 01 5f a1 90 01 04 83 c0 90 01 01 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GT_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8a 45 00 8d 7f 01 88 47 ff 8d 6d 90 01 01 8d 41 90 01 01 4e 03 c6 0f b7 c8 2b 0d 90 01 04 83 e9 90 01 01 85 f6 75 90 00 } //0a 00 
		$a_02_1 = {8d 4a b4 8b b4 07 90 01 04 88 0d 90 01 04 b9 f0 ff ff ff 2b cb 03 d1 8d 8e 90 01 04 89 15 90 01 04 89 0d 90 01 04 89 8c 07 90 01 04 83 c0 04 3d 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GT_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2a d9 0f b6 c0 2a da 8b 15 90 01 04 03 c7 03 c1 80 eb 90 01 01 89 44 24 90 01 01 8b 7c 24 90 01 01 a3 90 01 04 a0 90 01 04 2a 44 24 90 01 01 2c 04 88 44 24 90 01 01 89 44 24 90 01 01 a2 90 01 04 8b c2 2b c1 2b d7 90 00 } //0a 00 
		$a_02_1 = {89 01 83 c1 90 01 01 a3 90 01 04 33 c0 83 6c 24 90 01 01 01 89 44 24 90 01 01 a3 90 01 04 89 4c 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}