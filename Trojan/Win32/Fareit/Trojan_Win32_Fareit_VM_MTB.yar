
rule Trojan_Win32_Fareit_VM_MTB{
	meta:
		description = "Trojan:Win32/Fareit.VM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 10 0f b6 14 3a 33 c2 3d 90 01 04 76 90 00 } //01 00 
		$a_01_1 = {8b 55 10 88 04 3a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_VM_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.VM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 06 03 c3 73 90 01 01 e8 90 01 04 50 68 90 01 04 ff 15 90 01 05 ff 06 81 3e 90 01 04 75 90 00 } //01 00 
		$a_01_1 = {8a 45 08 5a 30 02 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_VM_MTB_3{
	meta:
		description = "Trojan:Win32/Fareit.VM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {e8 c3 29 f9 ff 8a 84 85 e8 fb ff ff 30 06 } //01 00 
		$a_03_1 = {8a 84 9d e8 fb ff ff 88 45 90 01 01 89 c0 89 f6 89 d2 87 ff 8b 84 bd e8 fb ff ff 89 84 9d e8 fb ff ff 90 90 89 db 90 90 33 c0 8a 45 90 01 01 89 84 bd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_VM_MTB_4{
	meta:
		description = "Trojan:Win32/Fareit.VM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 33 d2 52 50 8b 03 99 03 04 24 13 54 24 04 83 c4 90 01 01 c6 00 90 01 01 ff 03 81 3b 90 01 04 75 90 00 } //01 00 
		$a_00_1 = {44 4e 59 39 76 32 44 77 59 6c 37 63 54 55 61 4b 36 69 34 5a 53 68 58 6e 75 4f 63 44 66 6e 6d 70 76 54 } //01 00  DNY9v2DwYl7cTUaK6i4ZShXnuOcDfnmpvT
		$a_03_2 = {68 68 17 47 00 e8 90 01 04 4b 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}