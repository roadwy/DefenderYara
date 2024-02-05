
rule Trojan_Win32_Gozi_GU_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8a 04 37 8d 76 01 88 46 ff 4a a1 90 01 04 2b 05 90 01 04 8b 0d 90 01 04 1b 0d 90 01 04 3d 90 01 04 75 90 02 06 a0 90 01 04 2c 04 02 05 90 01 04 02 c0 2c 30 a2 90 01 04 85 d2 75 90 01 01 8b 2d 90 01 04 8b 44 24 90 01 01 2b dd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GU_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {4a 8d 76 01 b8 90 01 04 8d 7f 01 2b c2 03 c8 8a 47 ff 89 0d 90 01 04 88 46 ff 8b 0d 90 01 04 83 c1 90 01 01 85 d2 75 90 00 } //0a 00 
		$a_02_1 = {2b c1 8b 0d 90 01 04 a3 90 01 04 8b 84 11 90 01 04 05 90 01 04 a3 90 01 04 89 84 11 90 01 04 b9 0d 00 00 00 a1 90 01 04 83 c2 04 2b c8 0f b7 c9 81 fa 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}