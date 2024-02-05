
rule Trojan_Win32_Thedlowner_A{
	meta:
		description = "Trojan:Win32/Thedlowner.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 55 52 5c 4e 4f 49 53 52 45 56 54 4e 45 52 52 55 43 5c 53 57 4f 44 4e 49 57 5c 54 46 4f 53 4f 52 43 49 4d 5c 45 52 41 57 54 46 4f 53 } //01 00 
		$a_01_1 = {56 65 72 79 49 6d 70 6f 72 74 61 6e 74 57 69 6e 64 6f 77 73 46 69 6c 65 00 } //01 00 
		$a_01_2 = {4e 61 6f 20 74 65 6d 20 4e 41 44 41 00 } //01 00 
		$a_01_3 = {67 68 68 6c 6c 73 79 73 2e 65 78 65 00 } //01 00 
		$a_01_4 = {5c 6c 6f 61 64 65 72 49 6e 69 2e 69 6e 69 } //00 00 
	condition:
		any of ($a_*)
 
}