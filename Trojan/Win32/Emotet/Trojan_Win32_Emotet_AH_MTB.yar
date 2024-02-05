
rule Trojan_Win32_Emotet_AH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 d0 8d 04 bf 2b d0 8b 44 24 90 01 01 03 d1 8b 0d 90 01 04 0f b6 14 8a 30 10 8b 44 24 90 01 01 40 89 44 24 90 01 01 3b 44 24 90 01 01 0f 82 90 00 } //01 00 
		$a_01_1 = {74 45 26 38 61 28 3e 24 69 66 69 39 3c 69 72 26 6e 2b 33 47 4b 69 48 32 54 59 6f 24 77 6b 52 6d 52 39 44 70 42 50 5a 75 4d 6e 37 41 69 6b 47 41 24 74 3f 71 4c 41 5f 4c 37 4e 5a 5a 78 23 4d 71 35 2b 24 72 46 36 41 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_AH_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {66 39 38 71 39 25 50 24 44 61 64 46 75 29 56 32 67 59 6a 23 79 6c 58 50 3f 71 24 32 5a 5a 77 59 40 42 6a 35 4f 55 } //01 00 
		$a_01_1 = {6d 62 6d 61 62 70 74 65 62 6b 6a 63 64 6c 67 74 6a 6d 73 6b 6a 77 74 73 64 68 6a 62 6d 6b 6d 77 74 72 61 6b } //01 00 
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_3 = {44 69 73 61 62 6c 65 54 68 72 65 61 64 4c 69 62 72 61 72 79 43 61 6c 6c 73 } //00 00 
	condition:
		any of ($a_*)
 
}