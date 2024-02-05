
rule Trojan_Win32_Emotet_PAH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {59 59 0f b6 0c 10 8b 45 90 01 01 0f b6 04 10 03 c8 81 e1 90 01 04 79 90 01 01 49 83 c9 90 01 01 41 0f b6 c1 8b 4d 90 01 01 8a 04 10 30 04 0e 47 8b 45 90 01 01 8b 55 90 01 01 3b 7d 90 01 01 0f 8c 90 01 04 8b 7d 90 01 01 8b 45 90 01 01 5e 88 5f 90 01 01 88 07 5f 5b 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_PAH_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.PAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 00 50 e8 90 01 04 8b 4c 24 90 01 01 8b 44 24 90 01 01 8b 35 90 01 04 8b d1 2b 15 90 01 04 41 03 c2 0f b6 54 90 01 02 8a 14 32 30 10 3b 4c 24 90 01 01 89 4c 24 90 01 01 0f 8c 90 01 04 8a 4c 24 90 01 01 8b 44 90 01 01 24 8a 54 24 90 01 01 5f 5e 5d 5b 88 50 90 01 01 88 08 83 c4 08 c3 90 00 } //01 00 
		$a_03_1 = {99 f7 fb 8a c2 88 45 90 01 01 0f b6 c0 89 45 90 01 01 03 c1 50 57 e8 90 00 } //01 00 
		$a_03_2 = {99 f7 f9 0f b6 c2 8a 04 38 30 03 8b 45 90 01 01 8b 5d 90 01 01 3b 75 90 01 01 7c 90 02 04 8b 75 90 01 01 8a 45 90 01 01 5f 5b 88 06 8a 45 90 01 01 88 46 90 01 01 5e 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}