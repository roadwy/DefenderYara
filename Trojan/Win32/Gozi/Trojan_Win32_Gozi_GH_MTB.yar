
rule Trojan_Win32_Gozi_GH_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b d7 2b d0 81 c2 90 01 04 8b c2 6b d2 90 01 01 8b ee f7 dd 2b ea 03 dd 89 0d 90 01 04 89 1d 90 01 04 ba 90 01 04 0f b7 2d 90 01 04 3b cd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GH_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 05 a1 90 01 04 50 8b 0d 90 01 04 51 e8 90 01 04 03 f0 8b 15 90 01 04 2b d6 89 15 90 01 04 a1 90 01 04 8b 0d 90 01 04 8d 54 01 90 01 01 88 15 90 01 04 ff 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GH_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8a 10 88 91 90 01 04 83 c1 01 33 c0 8d a4 24 00 00 00 00 3b 90 01 01 74 90 00 } //0a 00 
		$a_02_1 = {0f b6 d0 03 d6 8d 54 1a 90 01 01 8b 5c 24 90 01 01 89 15 90 01 04 8a 54 24 90 01 01 81 c5 90 01 04 02 d1 80 ea 90 01 01 89 2b 83 c3 90 01 01 02 c2 83 6c 24 90 01 01 01 89 2d 90 01 04 89 5c 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}