
rule Trojan_Win32_Ursnif_A_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {04 34 02 c0 02 c2 02 44 24 14 89 44 24 18 a2 90 01 04 8b 44 24 14 81 c5 9c 94 4d 01 8a 0d 90 01 04 0f b7 f0 8b c6 2b c3 8b 5c 24 20 83 c0 04 89 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_A_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {05 b8 94 5b 01 89 44 24 14 89 02 a3 90 01 04 8d 04 75 e1 ff ff ff 0f b7 d0 8b c6 3b da 8b 5c 24 20 0f 42 1d 90 01 04 2b c2 03 05 90 01 04 83 44 24 10 04 90 00 } //01 00 
		$a_02_1 = {bf 49 0b 01 00 c7 44 24 44 42 36 81 00 0f 42 df 2b 05 90 01 04 03 c7 8b 3d 90 01 04 39 3d 90 01 04 89 44 24 1c a3 90 01 04 b8 56 00 00 00 0f 42 d8 a1 90 01 04 2b 05 90 01 04 2b d7 83 c6 c5 83 c0 56 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}