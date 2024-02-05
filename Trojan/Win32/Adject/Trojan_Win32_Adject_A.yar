
rule Trojan_Win32_Adject_A{
	meta:
		description = "Trojan:Win32/Adject.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3f 69 64 3d 25 73 26 61 70 70 3d 52 45 50 22 20 62 6f 72 64 65 72 3d 30 } //01 00 
		$a_01_1 = {3c 69 6d 67 20 73 72 63 3d 22 68 74 74 70 3a 2f 2f 77 77 77 2e 25 73 } //01 00 
		$a_01_2 = {3f 75 3d 25 73 26 74 3d 25 73 26 77 3d 25 73 26 69 64 3d 25 73 } //01 00 
		$a_01_3 = {50 52 45 53 43 52 49 50 54 49 4f 4e } //01 00 
		$a_01_4 = {56 55 49 54 54 4f 4e } //00 00 
	condition:
		any of ($a_*)
 
}