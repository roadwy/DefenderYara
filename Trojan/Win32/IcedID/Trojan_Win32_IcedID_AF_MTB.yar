
rule Trojan_Win32_IcedID_AF_MTB{
	meta:
		description = "Trojan:Win32/IcedID.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {02 4c 24 07 2a c2 2a 44 24 08 02 c9 55 2a c1 0f b6 e9 56 2c 69 57 88 44 24 13 } //0a 00 
		$a_02_1 = {89 4d fc 8b 15 90 01 04 81 c2 79 8f 0e 00 89 55 fc 6b 45 0c 4e 0f af 45 fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_IcedID_AF_MTB_2{
	meta:
		description = "Trojan:Win32/IcedID.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {8b 41 24 8b 08 8d 51 01 89 10 8a 44 24 04 88 01 0f b6 c0 eb 0b } //03 00 
		$a_80_1 = {44 6f 57 68 69 74 } //DoWhit  03 00 
		$a_80_2 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //GetTempPathA  03 00 
		$a_80_3 = {4d 6f 76 65 46 69 6c 65 45 78 41 } //MoveFileExA  03 00 
		$a_80_4 = {49 6d 61 67 65 4c 69 73 74 5f 44 72 61 67 53 68 6f 77 4e 6f 6c 6f 63 6b } //ImageList_DragShowNolock  00 00 
	condition:
		any of ($a_*)
 
}