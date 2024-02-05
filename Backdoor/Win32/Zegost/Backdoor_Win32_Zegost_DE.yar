
rule Backdoor_Win32_Zegost_DE{
	meta:
		description = "Backdoor:Win32/Zegost.DE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 1c 38 8b d1 81 e2 ff ff 00 00 8a 54 54 0c 32 da 41 88 1c 38 40 3b c6 72 de 5f 5b } //01 00 
		$a_03_1 = {5c c6 44 24 90 01 01 6f c6 44 24 90 01 01 75 c6 44 24 90 01 01 72 c6 44 24 90 01 01 6c c6 44 24 90 01 01 6f c6 44 24 90 01 01 67 c6 44 24 90 01 01 2e c6 44 24 90 01 01 64 c6 44 24 90 01 01 61 c6 44 24 90 01 01 74 c6 44 24 90 01 01 00 ff 90 00 } //00 00 
		$a_00_2 = {78 } //d2 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Zegost_DE_2{
	meta:
		description = "Backdoor:Win32/Zegost.DE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 11 32 54 90 01 02 8b 90 01 02 03 90 01 02 88 10 66 8b 90 01 02 66 83 c1 01 66 89 90 01 02 eb 90 00 } //01 00 
		$a_00_1 = {c6 45 f4 5c c6 45 f5 6f c6 45 f6 75 c6 45 f7 72 c6 45 f8 6c c6 45 f9 6f c6 45 fa 67 c6 45 fb 2e c6 45 fc 64 c6 45 fd 61 c6 45 fe 74 c6 45 ff 00 } //01 00 
		$a_03_2 = {fb ff ff 5c c6 85 90 01 01 fb ff ff 6f c6 85 90 01 01 fb ff ff 75 c6 85 90 01 01 fb ff ff 72 c6 85 90 01 01 fb ff ff 6c c6 85 90 01 01 fb ff ff 6f c6 85 90 01 01 fb ff ff 67 c6 85 90 01 01 fb ff ff 2e c6 85 90 01 01 fb ff ff 64 c6 85 90 01 01 fb ff ff 61 c6 85 90 01 01 fb ff ff 74 c6 85 90 01 01 fb ff ff 00 90 00 } //00 00 
		$a_00_3 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}