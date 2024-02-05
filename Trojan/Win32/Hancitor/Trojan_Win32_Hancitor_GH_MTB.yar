
rule Trojan_Win32_Hancitor_GH_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b6 c8 3b 0d 90 01 04 74 90 01 01 29 1e 8d 43 90 01 01 02 c2 66 8b d7 0f b6 c8 66 2b d1 a2 90 01 04 66 83 ea 90 01 01 0f b7 d2 83 ee 90 01 01 81 fe 90 01 04 7f 90 01 01 8b 44 24 90 01 01 8b 4c 24 90 01 01 85 ed 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Hancitor_GH_MTB_2{
	meta:
		description = "Trojan:Win32/Hancitor.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8a 11 88 10 8b 45 90 01 01 83 c0 01 89 45 90 01 01 8b 4d 90 01 01 83 c1 01 89 4d 90 01 01 8b 15 90 01 04 83 ea 90 01 01 2b 15 90 01 04 89 55 90 01 01 c7 45 90 01 01 00 00 00 00 eb 90 00 } //0a 00 
		$a_02_1 = {0f b7 55 f4 a1 90 01 04 8d 4c 02 90 01 01 03 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 81 c2 90 01 04 89 15 90 01 04 a1 90 01 04 03 45 90 01 01 8b 0d 90 01 04 89 88 90 01 04 8b 15 90 01 04 a1 90 01 04 8d 4c 10 01 66 89 4d 90 01 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}