
rule Trojan_Win32_Emotet_DFH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 23 13 00 00 f7 f9 8b 4c 24 18 8b 84 24 90 01 04 8a 1c 01 8a 54 14 20 32 da 88 1c 01 90 00 } //01 00 
		$a_81_1 = {6b 75 50 77 36 79 6b 7a 55 55 49 44 35 77 57 42 65 7a 6e 36 76 62 6f 37 70 43 73 5a 33 71 4f 31 69 76 58 70 30 43 37 4f } //00 00  kuPw6ykzUUID5wWBezn6vbo7pCsZ3qO1ivXp0C7O
	condition:
		any of ($a_*)
 
}