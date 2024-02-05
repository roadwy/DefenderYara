
rule Trojan_Win32_ClipBanker_DP_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 73 24 8b 45 fc 33 d2 f7 75 14 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 33 c1 8b 4d 08 03 4d fc 88 01 eb cb } //01 00 
		$a_00_1 = {8b 55 f8 83 c2 01 89 55 f8 8b 45 f8 3b 45 fc 73 13 8b 4d f0 03 4d f8 8b 55 f8 8b 45 e8 8a 14 50 88 11 eb dc } //01 00 
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00 
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}