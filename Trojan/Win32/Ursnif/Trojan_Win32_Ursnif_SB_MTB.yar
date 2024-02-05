
rule Trojan_Win32_Ursnif_SB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {62 45 4e 48 57 52 4a 4e 52 77 40 23 47 48 4e 65 2e 70 64 62 } //01 00 
		$a_81_1 = {5a 4b 39 20 4c 54 44 } //01 00 
		$a_81_2 = {37 20 42 72 6f 78 62 6f 75 72 6e 65 20 52 6f 61 64 } //01 00 
		$a_81_3 = {43 65 72 74 75 6d 20 45 56 20 54 53 41 20 53 48 41 32 } //01 00 
		$a_01_4 = {68 00 74 00 6e 00 52 00 6e 00 65 00 } //01 00 
		$a_81_5 = {7a 6e 66 75 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_SB_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.SB!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {66 89 44 24 14 8b c6 0f af 44 24 0c 83 64 24 24 00 69 c0 e3 48 00 00 0f b7 c0 57 0f b7 f8 6a 00 89 44 24 14 6a 02 } //0a 00 
		$a_01_1 = {66 83 c0 08 69 f6 84 04 00 00 0f b7 e8 0f b7 c5 03 f0 6b c0 4b 03 c3 89 6c 24 0c 03 e8 8b c5 69 c0 63 3b } //00 00 
	condition:
		any of ($a_*)
 
}