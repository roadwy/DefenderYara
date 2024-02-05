
rule Trojan_Win32_Gozi_GM_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {66 2b d0 0f b7 c2 8b 55 90 01 01 89 45 90 01 01 0f b7 75 90 01 01 8d 42 90 01 01 02 c8 8d 04 b7 88 0d 90 01 04 03 c6 a3 90 01 04 0f b6 c1 2b c2 83 c0 90 01 01 89 45 90 01 01 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GM_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 08 8b 55 f0 8b 45 fc 8d 8c 10 90 01 04 89 4d 90 01 01 8b 15 90 01 04 89 15 90 01 04 8b 45 90 01 01 a3 90 01 04 8b 4d 90 01 01 83 c1 90 01 01 89 4d 90 00 } //01 00 
		$a_02_1 = {83 e9 21 89 0d 90 01 04 8b 0d 90 01 04 83 c1 90 01 01 a1 90 01 04 a3 90 01 04 b8 90 01 04 b8 90 01 04 a1 90 02 c8 31 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GM_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b6 45 ef 83 e8 90 01 01 99 03 05 90 02 04 13 15 90 02 04 a2 90 02 04 0f b7 05 90 02 04 3d 90 02 04 90 18 0f b6 45 90 01 01 83 e8 90 01 01 99 03 45 90 01 01 13 55 90 01 01 a3 90 02 04 89 15 90 02 04 a1 90 02 04 05 90 02 04 a3 90 02 04 8b 0d 90 02 04 03 4d 90 01 01 8b 15 90 02 04 89 91 90 02 04 a1 90 02 04 83 e8 90 01 01 33 c9 2b 05 90 02 04 1b 0d 90 02 04 88 45 90 01 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}