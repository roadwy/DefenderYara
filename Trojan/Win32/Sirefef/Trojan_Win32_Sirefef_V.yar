
rule Trojan_Win32_Sirefef_V{
	meta:
		description = "Trojan:Win32/Sirefef.V,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b6 02 3d ff 00 00 00 75 7a 8b 90 01 02 0f b6 51 01 83 fa 15 75 65 8b 90 01 02 8b 48 02 90 00 } //01 00 
		$a_00_1 = {7c 50 4f 53 54 20 2f 61 6a 61 78 2f 63 68 61 74 2f 73 65 6e 64 2e 70 68 70 3f } //01 00  |POST /ajax/chat/send.php?
		$a_02_2 = {63 00 6f 00 6f 00 6c 00 63 00 6f 00 72 00 65 00 90 01 04 2e 00 64 00 6c 00 6c 00 90 00 } //01 00 
		$a_00_3 = {53 6b 69 6e 75 78 57 69 6e 64 6f 77 } //00 00  SkinuxWindow
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Sirefef_V_2{
	meta:
		description = "Trojan:Win32/Sirefef.V,SIGNATURE_TYPE_ARHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b6 02 3d ff 00 00 00 75 7a 8b 90 01 02 0f b6 51 01 83 fa 15 75 65 8b 90 01 02 8b 48 02 90 00 } //01 00 
		$a_00_1 = {7c 50 4f 53 54 20 2f 61 6a 61 78 2f 63 68 61 74 2f 73 65 6e 64 2e 70 68 70 3f } //01 00  |POST /ajax/chat/send.php?
		$a_02_2 = {63 00 6f 00 6f 00 6c 00 63 00 6f 00 72 00 65 00 90 01 04 2e 00 64 00 6c 00 6c 00 90 00 } //01 00 
		$a_00_3 = {53 6b 69 6e 75 78 57 69 6e 64 6f 77 } //00 00  SkinuxWindow
	condition:
		any of ($a_*)
 
}