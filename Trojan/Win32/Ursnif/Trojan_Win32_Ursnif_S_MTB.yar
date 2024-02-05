
rule Trojan_Win32_Ursnif_S_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 e4 b9 90 01 04 89 45 e0 31 d2 f7 f1 8a 1c 15 90 01 04 8b 4d ec 8b 55 e0 8a 3c 11 28 df 8b 75 e8 88 3c 16 83 c2 01 8b 7d f0 39 fa 89 55 e4 74 c4 eb ca 90 00 } //01 00 
		$a_03_1 = {31 c9 8d 55 d6 89 45 a0 89 55 9c 89 4d 98 8b 45 98 8a 0c 05 90 01 04 8a 14 05 90 01 04 28 ca 88 54 05 d6 83 c0 01 83 f8 14 89 45 98 75 de 90 00 } //00 00 
		$a_00_2 = {78 } //96 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_S_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 17 13 d8 89 35 90 01 02 43 00 8b 44 24 1c 0f b7 c8 8b c1 89 1d 90 01 02 43 00 2b 05 90 01 02 43 00 05 1a b9 00 00 89 54 24 18 a3 90 01 02 43 00 8d 81 1b ff ff ff 03 c5 3d 2a 0e 00 00 7c 1a 6b c1 4d 2b c5 99 8b da 8b f0 8b 54 24 18 89 35 90 01 02 43 00 89 1d 90 01 02 43 00 6b 6c 24 10 4d 81 c2 d8 e9 eb 01 6a 00 90 00 } //01 00 
		$a_02_1 = {2b 44 24 28 1b d7 03 d8 89 1d 90 01 02 43 00 13 ea 89 2d 90 01 02 43 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}